import zlib
from typing import Dict, Iterator, List, Optional, Type

from pdfminer.ascii85 import ascii85decode

from . import pdfparser
from .kaitai.parser import KaitaiParser
from .fileutils import Tempfile
from .kaitaimatcher import ast_to_matches
from .logger import getStatusLogger
from .polyfile import Match, Matcher, Submatch, submatcher

log = getStatusLogger("PDF")


def token_length(tok):
    if hasattr(tok, 'token'):
        return len(tok.token)
    else:
        return len(tok[1])


def content_length(content):
    return content[-1].offset.offset - content[0].offset.offset + token_length(content[-1])


def _emit_dict(parsed, parent, pdf_offset):
    dict_obj = Submatch(
        "PDFDictionary",
        '',
        relative_offset=parsed.start.offset.offset - parent.offset + pdf_offset,
        length=parsed.end.offset.offset - parsed.start.offset.offset + len(parsed.end.token),
        parent=parent
    )
    yield dict_obj
    for key, value in parsed:
        if isinstance(value, pdfparser.ParsedDictionary):
            value_end = value.end.offset.offset + len(value.end.token)
        else:
            if not value:
                value_end = key.offset.offset + len(key.token)
            else:
                value_end = value[-1].offset.offset + len(value[-1].token)
        pair_offset = key.offset.offset - dict_obj.offset
        pair = Submatch(
            "KeyValuePair",
            '',
            relative_offset=pair_offset + pdf_offset,
            length=value_end - key.offset.offset,
            parent=dict_obj
        )
        yield pair
        yield Submatch(
            "Key",
            key.token,
            relative_offset=0,
            length=len(key.token),
            parent=pair
        )
        if isinstance(value, pdfparser.ParsedDictionary):
            yield from _emit_dict(value, pair, pdf_offset)
        elif value:
            value_length = value[-1].offset.offset + len(value[-1].token) - value[0].offset.offset
            yield Submatch(
                "Value",
                ''.join(v.token for v in value),
                relative_offset=value[0].offset.offset - key.offset.offset,
                length=value_length,
                parent=pair
            )


FILTERS_BY_NAME: Dict[str, Type["StreamFilter"]] = {}


class StreamFilter:
    name: str

    def __init__(self, next_decoder: Optional["StreamFilter"] = None):
        self.next_decoder: Optional[StreamFilter] = next_decoder

    def __init_subclass__(cls, **kwargs):
        FILTERS_BY_NAME[f"/{cls.name}Decode"] = cls

    def decode(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        raise NotImplementedError()

    def match(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        for submatch in self.decode(matcher, raw_content, parent):
            yield submatch
            if submatch.decoded is None:
                if self.next_decoder is not None:
                    log.warning(f"Expected submatch submatch {submatch!r} from decoded by {self.__class__.__name__} "
                                "to have a `decoded` member, but it was `None`")
                continue
            if self.next_decoder is None:
                # recursively match against the deflated contents
                with Tempfile(submatch.decoded) as f:
                    yield from matcher.match(f, parent=submatch)
            else:
                yield from self.next_decoder.match(matcher, submatch.decoded, submatch)


class FlateDecoder(StreamFilter):
    name = "Flate"

    def decode(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        try:
            decoded = zlib.decompress(raw_content)
            yield Submatch(
                f"{self.name}Encoded",
                raw_content,
                relative_offset=0,
                length=len(raw_content),
                parent=parent,
                decoded=decoded
            )
        except zlib.error:
            log.warn(f"DEFLATE decoding error near offset {parent.offset}")


class DCTDecoder(StreamFilter):
    name = "DCT"

    def decode(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        if raw_content[:1] != b'\xff':
            return
        # This is most likely a JPEG image
        try:
            ast = KaitaiParser.load("image/jpeg.ksy").parse(raw_content).ast
        except Exception as e:
            log.error(str(e))
            ast = None
        if ast is not None:
            yield from ast_to_matches(ast, parent=parent)


class ASCIIHexDecoder(StreamFilter):
    name = "ASCIIHex"

    def decode(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        data = bytearray()
        for byte_str in raw_content.replace(b"\n", b" ").split(b" "):
            byte_str = byte_str.strip()
            if byte_str.endswith(b">"):
                byte_str = byte_str[:-1].strip()
            try:
                data.append(int(byte_str, 16))
            except ValueError:
                log.warning(f"Invalid byte string {byte_str!r} near offset {parent.offset}")
                return
        yield Submatch(
            f"{self.name}Encoded",
            raw_content,
            relative_offset=0,
            length=len(raw_content),
            parent=parent,
            decoded=bytes(data)
        )


class ASCII85Decoder(StreamFilter):
    name = "ASCII85"

    def decode(self, matcher: Matcher, raw_content: bytes, parent: Submatch) -> Iterator[Submatch]:
        decoded = ascii85decode(raw_content)
        yield Submatch(
            f"{self.name}Encoded",
            raw_content,
            relative_offset=0,
            length=len(raw_content),
            parent=parent,
            decoded=bytes(decoded)
        )


def parse_object(file_stream, object, matcher: Matcher, parent=None):
    log.status('Parsing PDF obj %d %d' % (object.id, object.version))
    objtoken, objid, objversion, endobj = object.objtokens
    pdf_length=endobj.offset.offset - object.content[0].offset.offset + 1 + len(endobj.token)
    if parent is None or isinstance(parent, PDF):
        parent_offset = 0
    else:
        parent_offset = parent.offset
    obj = Submatch(
        name="PDFObject",
        display_name=f"PDFObject{object.id}.{object.version}",
        match_obj=(object.id, object.version),
        relative_offset=objid.offset.offset - parent_offset,
        length=pdf_length + object.content[0].offset.offset - objid.offset.offset,
        parent=parent
    )
    yield obj
    yield Submatch(
        "PDFObjectID",
        object.id,
        relative_offset=0,
        length=len(objid.token),
        parent=obj
    )
    yield Submatch(
        "PDFObjectVersion",
        object.version,
        relative_offset=objversion.offset.offset - objid.offset.offset,
        length=len(objversion.token),
        parent=obj
    )
    log.debug(' Type: %s' % pdfparser.ConditionalCanonicalize(object.GetType(), False))
    log.debug(' Referencing: %s' % ', '.join(map(lambda x: '%s %s %s' % x, object.GetReferences())))
    dataPrecedingStream = object.ContainsStream()
    if dataPrecedingStream:
        log.debug(' Contains stream')
        log.debug(' %s' % pdfparser.FormatOutput(dataPrecedingStream, False))
        oPDFParseDictionary = pdfparser.cPDFParseDictionary(dataPrecedingStream, False)
    else:
        log.debug(' %s' % pdfparser.FormatOutput(object.content, False))
        oPDFParseDictionary = pdfparser.cPDFParseDictionary(object.content, False)
    #log.debug('')
    #pp = BytesIO()
    #oPDFParseDictionary.PrettyPrint('  ', stream=pp)
    #pp.flush()
    #dict_content = pp.read()
    #log.debug(dict_content)
    dict_offset = oPDFParseDictionary.content[0].offset.offset - objid.offset.offset
    dict_length = content_length(oPDFParseDictionary.content)
    if oPDFParseDictionary.parsed is not None:
        yield from _emit_dict(oPDFParseDictionary.parsed, obj, parent.offset)
    #log.debug('')
    #log.debug('')
    content_start = dict_offset + dict_length
    content_len = endobj.offset.offset - content_start - objid.offset.offset
    if content_len > 0:
        content = Submatch(
            "PDFObjectContent",
            (),
            relative_offset=content_start,
            length=content_len,
            parent=obj
        )
        yield content
        stream_len = None
        filters: List[StreamFilter] = []
        if oPDFParseDictionary.parsed is not None:
            if '/Filter' in oPDFParseDictionary.parsed:
                filter_value = oPDFParseDictionary.parsed["/Filter"].strip()
                if filter_value.startswith("[") and filter_value.endswith("]"):
                   filter_value = str(filter_value[1:-1])
                for filter in filter_value.split(" "):
                    if len(filter.strip()) == 0:
                        continue
                    elif filter.strip() not in FILTERS_BY_NAME:
                        log.warn(f"Unimplemented PDF filter: {filter.strip()}")
                    else:
                        new_filter = FILTERS_BY_NAME[filter.strip()]()
                        if filters:
                            filters[-1].next_decoder = new_filter
                        filters.append(new_filter)
            if '/Length' in oPDFParseDictionary.parsed:
                try:
                    stream_len = int(oPDFParseDictionary.parsed['/Length'])
                except ValueError:
                    pass
        old_pos = file_stream.tell()
        try:
            file_stream.seek(content.root_offset)
            raw_content = file_stream.read(content_len)
        finally:
            file_stream.seek(old_pos)
        streamtoken = b'stream'
        if raw_content.startswith(streamtoken):
            raw_content = raw_content[len(streamtoken):]
            if raw_content.startswith(b'\r'):
                streamtoken += b'\r'
                raw_content = raw_content[1:]
            if raw_content.startswith(b'\n'):
                streamtoken += b'\n'
                raw_content = raw_content[1:]
                if raw_content.endswith(b'\n') or raw_content.endswith(b'\r'):
                    endtoken = b'endstream'
                    if raw_content.endswith(b'\r\n'):
                        endtoken += b'\r\n'
                    elif raw_content.endswith(b'\r'):
                        endtoken += b'\r'
                    else:
                        endtoken += b'\n'
                    if raw_content.endswith(endtoken):
                        raw_content = raw_content[:-len(endtoken)]
                        if raw_content.endswith(b'\n') and stream_len is not None and len(raw_content) > stream_len:
                            endtoken = b'\n' + endtoken
                            raw_content = raw_content[:-1]
                        yield Submatch(
                            "StartStream",
                            streamtoken,
                            relative_offset=0,
                            length=len(streamtoken),
                            parent=content
                        )
                        streamcontent = Submatch(
                            "StreamContent",
                            raw_content,
                            relative_offset=len(streamtoken),
                            length=len(raw_content),
                            parent=content
                        )
                        yield streamcontent
                        if filters:
                            yield from filters[0].match(matcher, raw_content, streamcontent)
                        yield Submatch(
                           "EndStream",
                            endtoken,
                            relative_offset=len(streamtoken) + len(raw_content),
                            length=len(endtoken),
                            parent=content
                        )
    log.clear_status()


def parse_pdf(file_stream, matcher: Matcher, parent=None):
    if parent is None or isinstance(parent, PDF):
        parent_offset = 0
    else:
        parent_offset = parent.offset
    with file_stream.tempfile(suffix='.pdf') as pdf_path:
        parser = pdfparser.cPDFParser(pdf_path, True)
        while True:
            object = parser.GetObject()
            if object is None:
                break
            elif object.type == pdfparser.PDF_ELEMENT_COMMENT:
                log.debug(f"PDF comment at {object.offset}, length {len(object.comment)}")
                yield Submatch(
                    name='PDFComment',
                    match_obj=object,
                    relative_offset=object.offset.offset - parent_offset,
                    length=len(object.comment),
                    parent=parent
                )
            elif object.type == pdfparser.PDF_ELEMENT_XREF:
                log.debug('PDF xref')
                yield Submatch(
                    name='PDFXref',
                    match_obj=object,
                    relative_offset=object.content[0].offset.offset - parent_offset,
                    length=content_length(object.content),
                    parent=parent
                )
            elif object.type == pdfparser.PDF_ELEMENT_TRAILER:
                pdfparser.cPDFParseDictionary(object.content[1:], False)
                yield Submatch(
                    name='PDFTrailer',
                    match_obj=object,
                    relative_offset=object.content[0].offset.offset - parent_offset,
                    length=content_length(object.content),
                    parent=parent
                )
            elif object.type == pdfparser.PDF_ELEMENT_STARTXREF:
                yield Submatch(
                    name='PDFStartXRef',
                    match_obj=object.index,
                    relative_offset=object.offset.offset - parent_offset,
                    length=object.length,
                    parent=parent
                )
            elif object.type == pdfparser.PDF_ELEMENT_INDIRECT_OBJECT:
                yield from parse_object(file_stream, object, matcher=matcher, parent=parent)


from pdfminer.pdfparser import PDFParser as PDFMinerParser, PDFStream, PDFObjRef
from pdfminer.psparser import PSBaseParserToken, PSKeyword, PSObject, PSLiteral, PSStackEntry, ExtraT
from pdfminer.pdfdocument import (
    PDFDocument, PDFXRef, KWD, PDFNoValidXRef, PSEOF, dict_value, LITERAL_XREF, LITERAL_OBJSTM, LITERAL_CATALOG,
    DecipherCallable, PDFObjectNotFound
)
from pdfminer.pdftypes import (
    LITERALS_FLATE_DECODE, LITERALS_ASCIIHEX_DECODE, LITERALS_CCITTFAX_DECODE, LITERALS_RUNLENGTH_DECODE,
    LITERAL_CRYPT, LITERALS_LZW_DECODE, LITERALS_DCT_DECODE, LITERALS_JBIG2_DECODE, LITERALS_ASCII85_DECODE,
    int_value, apply_png_predictor
)
from typing import Tuple, Union

from .fileutils import FileStream


def load_trailer(self, parser: "PDFParser") -> None:
    try:
        (_, kwd) = parser.nexttoken()
        assert kwd == KWD(b'trailer'), f"{kwd!s} != {KWD(b'trailer')!s}"
        flush_before = parser.auto_flush
        try:
            # This might be a bug in pdfminer, or it's just that we are using it wrong, but we need to
            # flush our entire token stack to the results list in order to parse the trailer dict:
            parser.auto_flush = True
            (_, dic) = parser.nextobject()
        finally:
            parser.auto_flush = flush_before
    except PSEOF:
        x = parser.pop(1)
        if not x:
            raise PDFNoValidXRef('Unexpected EOF - file corrupted')
        (_, dic) = x[0]
    self.trailer.update(dict_value(dic))
    log.debug('trailer=%r', self.trailer)
    return

PDFXRef.load_trailer = load_trailer


class PSToken:
    pdf_offset: int
    pdf_bytes: int

    def __new__(cls, *args, **kwargs):
        ret = super().__new__(cls, *args)
        ret.pdf_offset = kwargs["pdf_offset"]
        ret.pdf_bytes = kwargs["pdf_bytes"]
        return ret

    def __int__(self):
        return PSInt(self, pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __float__(self):
        return PSFloat(self, pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __bytes__(self):
        if isinstance(self, PSBytes):
            return self
        else:
            return PSBytes(self, pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __hex__(self):
        return PSStr(super().__hex__(), pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __str__(self):
        return PSStr(super().__str__(), pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __repr__(self):
        return f"{self.__class__.__name__}({super().__repr__()}, pdf_offset={self.pdf_offset!r}, "\
               f"pdf_bytes={self.pdf_bytes!r})"


class PSInt(PSToken, int):
    pass


class PSSequence(PSToken):
    def __getitem__(self, item):
        if isinstance(item, int):
            value = super().__getitem__(item)
            return make_ps_object(value, pdf_offset=self.pdf_offset+item, pdf_bytes=self.pdf_bytes-item)
        elif isinstance(item, slice):
            if item.start is None:
                start = 0
            else:
                start = item.start
            if item.stop is None:
                stop = self.pdf_bytes
            else:
                stop = item.stop
            try:
                return self.__class__(
                    super().__getitem__(item),
                    pdf_offset=self.pdf_offset+start,
                    pdf_bytes=self.pdf_bytes-(stop - start)
                )
            except ValueError:
                if isinstance(self, PSBytes):
                    return PSBytes(
                        super().__getitem__(item),
                        pdf_offset=self.pdf_offset+start,
                        pdf_bytes=self.pdf_bytes-(stop - start)
                    )
                else:
                    raise
        else:
            return super().__getitem__(item)


class PSStr(PSSequence, str):
    def __new__(cls, *args, **kwargs):
        retval = super().__new__(cls, *args, **kwargs)
        if retval == "Linearized":
            breakpoint()
        return retval

    def encode(self, encoding: str = ..., errors: str = ...) -> bytes:
        return PSBytes(super().encode(encoding, errors), pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __str__(self):
        return str.__str__(self)


class PSBytes(PSSequence, bytes):
    def __new__(cls, *args, **kwargs):
        kwargs = dict(kwargs)
        if "pdf_bytes" not in kwargs:
            kwargs["pdf_bytes"] = len(args[0])
        return super().__new__(cls, *args, **kwargs)

    def decode(self, encoding: str = ..., errors: str = ...) -> PSStr:
        return PSStr(super().decode(encoding, errors), pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)


class PDFDeciphered(PSBytes):
    original_bytes: bytes

    def __new__(cls, *args, **kwargs):
        kwargs = dict(kwargs)
        if "pdf_bytes" not in kwargs:
            kwargs["pdf_bytes"] = len(args[0])
        if "original_bytes" in kwargs:
            original_bytes = kwargs["original_bytes"]
            del kwargs["original_bytes"]
        else:
            raise ValueError(f"{cls.__name__}.__init__ requires the `original_bytes` argument")
        ret = super().__new__(cls, *args, **kwargs)
        setattr(ret, "original_bytes", original_bytes)
        return ret


class PSFloat(PSToken, float):
    pass


class PSBool:
    def __init__(self, value: bool, pdf_offset: int, pdf_bytes: int):
        self.value: bool = value
        self.pdf_offset: int = pdf_offset
        self.pdf_bytes: int = pdf_bytes

    def __bool__(self):
        return self.value

    def __int__(self):
        return PSInt(int(self.value), pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __eq__(self, other):
        return self.value == bool(other)

    def __ne__(self, other):
        return self.value != bool(other)

    def __hash__(self):
        return hash(self.value)

    def __str__(self):
        return PSStr(self.value, pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)

    def __repr__(self):
        return f"{self.__class__.__name__}(value={self.value!r}, pdf_offset={self.pdf_offset!r}, "\
               f"pdf_bytes={self.pdf_bytes!r})"


class PDFLiteral(PSLiteral):
    def __init__(self, name: PSLiteral.NameType, pdf_offset: int, pdf_bytes: int):
        if isinstance(name, str) and not isinstance(name, PSStr):
            super().__init__(PSStr(name, pdf_offset=pdf_offset + 1, pdf_bytes=pdf_bytes))
        elif isinstance(name, bytes) and not isinstance(name, PSBytes):
            super().__init__(PSBytes(name, pdf_offset=pdf_offset + 1, pdf_bytes=pdf_bytes))
        else:
            super().__init__(name)

    @property
    def pdf_bytes(self) -> int:
        return self.name.pdf_bytes + 1  # add one to account for the leading "/"

    @property
    def pdf_offset(self) -> int:
        return self.name.pdf_offset - 1

    def __eq__(self, other):
        return isinstance(other, PSLiteral) and self.name == other.name


class PDFKeyword(PSKeyword):
    def __init__(self, name: bytes, pdf_offset: int, pdf_bytes: int):
        pdf_bytes = len(name)  # sometimes we actually lose the length of the token, so rely on the keyword name
        if not isinstance(name, PSBytes):
            super().__init__(PSBytes(name, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes))
        else:
            super().__init__(name)
        self.pdf_offset: int = pdf_offset
        self.pdf_bytes: int = pdf_bytes

    def __eq__(self, other):
        return isinstance(other, PSKeyword) and self.name == other.name

    def __repr__(self):
        return f"{self.__class__.__name__}({self.name!r}, pdf_offset={self.pdf_offset}, pdf_bytes={self.pdf_bytes})"

    def __str__(self):
        return f"/{self.name!s}"


PDFBaseParserToken = Union[PSFloat, PSBool, PDFLiteral, PSKeyword, PSBytes, PSInt]


"""
pdfminer.pdfdocument unfortunately tests for equality with these literals using `is` rather than `==`, so we must
return their singletons from a dict rather than our instrumented PDFLiteral objects:
"""
PROTECTED_LITERALS: Dict[str, PSLiteral] = {
    LITERAL_OBJSTM.name: LITERAL_OBJSTM,
    LITERAL_XREF.name: LITERAL_XREF,
    LITERAL_CATALOG.name: LITERAL_CATALOG
}

class PDFDict(dict, Dict[PSStr, Union[PDFBaseParserToken, PSStr, "PDFDict", "PDFList"]]):
    pdf_offset: int
    pdf_bytes: int

    def __init__(self, *args, **kwargs):
        kwargs = dict(kwargs)
        if "pdf_offset" in kwargs:
            del kwargs["pdf_offset"]
        if "pdf_bytes" in kwargs:
            del kwargs["pdf_bytes"]
        super().__init__(*args, **kwargs)

    def get(self, key, default = None):
        result = super().get(key, default)
        if isinstance(result, PDFLiteral) and result.name in PROTECTED_LITERALS:
            # we must return the protected literals as their singleton version:
            return PROTECTED_LITERALS[result.name]
        return result

    def __new__(cls, *args, pdf_offset: int, pdf_bytes: int, **kwargs):
        ret = super().__new__(cls, *args, **kwargs)
        ret.pdf_offset = pdf_offset
        ret.pdf_bytes = pdf_bytes
        return ret


class PDFList(PSSequence, list):
    @staticmethod
    def load(iterable) -> "PDFList":
        start_offset: Optional[int] = None
        end_offset: Optional[int] = None
        items = []
        for item in iterable:
            if hasattr(item, "pdf_offset") and hasattr(item, "pdf_bytes"):
                if start_offset is None or start_offset > item.pdf_offset:
                    start_offset = item.pdf_offset
                if end_offset is None or end_offset < item.pdf_offset + item.pdf_bytes:
                    end_offset = item.pdf_offset + item.pdf_bytes
            items.append(item)
        if start_offset is None or end_offset is None:
            raise ValueError(f"Cannot determine PDF bounds for list {items!r}")
        return PDFList(items, pdf_offset=start_offset, pdf_bytes=end_offset - start_offset)


def make_ps_object(value, pdf_offset: int, pdf_bytes: int) -> Union[PDFBaseParserToken, PSStr]:
    if isinstance(value, PSLiteral):
        return PDFLiteral(value.name, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes)
    # Unfortunately, we can't convert PSKeywords to PDFKeywords here because pdfminer requires them to be singletons
    # elif isinstance(value, PSKeyword):
    #     return PDFKeyword(value.name, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes)
    elif isinstance(value, PDFDict):
        value.pdf_offset = pdf_offset
        value.pdf_bytes = pdf_bytes
        return value
    elif isinstance(value, dict):
        return PDFDict(value, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes)
    elif isinstance(value, PSObject):
        setattr(value, "pdf_offset", pdf_offset)
        if isinstance(value, PSKeyword):
            # sometimes the byte count gets off, so set it to the name size
            pdf_bytes = len(value.name)
        setattr(value, "pdf_bytes", pdf_bytes)
        return value
    elif isinstance(value, int):
        supertype = PSInt
    elif isinstance(value, float):
        supertype = PSFloat
    elif isinstance(value, bool):
        supertype = PSBool
    elif isinstance(value, bytes):
        supertype = PSBytes
    elif isinstnace(value, str):
        supertype = PSStr
    else:
        raise NotImplementedError(f"Add suppport for PSSequences containing elements of type {type(value)}")
    return supertype(value, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes)


class DecodingError(bytes):
    message: Optional[str]

    def __new__(cls, *args, **kwargs):
        kwargs = dict(kwargs)
        if "message" in kwargs:
            message = kwargs["message"]
            del kwargs["message"]
        else:
            message = None
        ret = super().__new__(cls, b'')
        setattr(ret, "message", message)
        return ret


class PDFStreamFilter(PSBytes):
    name: str
    original_bytes: bytes
    error: Optional[DecodingError]

    def __new__(cls, *args, **kwargs):
        kwargs = dict(kwargs)
        if "pdf_bytes" not in kwargs:
            kwargs["pdf_bytes"] = len(args[0])
        if "original_bytes" in kwargs:
            original_bytes = kwargs["original_bytes"]
            del kwargs["original_bytes"]
        else:
            raise ValueError(f"{cls.__name__}.__init__ requires the `original_bytes` argument")
        if "name" in kwargs:
            name = kwargs["name"]
            del kwargs["name"]
        else:
            raise ValueError(f"{cls.__name__}.__init__ requires the `name` argument")
        if isinstance(args[0], DecodingError):
            error = args[0]
        else:
            error = None
        ret = super().__new__(cls, *args, **kwargs)
        setattr(ret, "original_bytes", original_bytes)
        setattr(ret, "name", name)
        setattr(ret, "error", error)
        return ret


class PNGPredictor(PSBytes):
    params: PDFDict
    original_bytes: bytes

    def __new__(cls, *args, **kwargs):
        kwargs = dict(kwargs)
        if "pdf_bytes" not in kwargs:
            kwargs["pdf_bytes"] = len(args[0])
        if "original_bytes" in kwargs:
            original_bytes = kwargs["original_bytes"]
            del kwargs["original_bytes"]
        else:
            raise ValueError(f"{cls.__name__}.__init__ requires the `original_bytes` argument")
        if "params" in kwargs:
            params = kwargs["params"]
            del kwargs["params"]
        else:
            raise ValueError(f"{cls.__name__}.__init__ requires the `params` argument")
        ret = super().__new__(cls, *args, **kwargs)
        setattr(ret, "original_bytes", original_bytes)
        setattr(ret, "params", params)
        return ret


class PDFObjectStream(PDFStream):
    def __init__(self, parent: PDFStream, pdf_offset: int, pdf_bytes: int):
        super().__init__(
            attrs=parent.attrs,
            rawdata=PSBytes(parent.rawdata, pdf_offset=pdf_offset, pdf_bytes=pdf_bytes),
            decipher=parent.decipher
        )
        self.parent: PDFStream = parent
        self.pdf_offset: int = pdf_offset
        self.pdf_bytes: int = pdf_bytes
        self.data = parent.data
        self.objid = parent.objid
        self.genno = parent.genno

    @property
    def data(self) -> Optional[PSBytes]:
        return self._data

    @data.setter
    def data(self, new_value: Optional[bytes]):
        if new_value is not None and not isinstance(new_value, PSBytes):
            self._data = PSBytes(new_value, pdf_offset=self.pdf_offset, pdf_bytes=self.pdf_bytes)
        else:
            self._data = new_value

    @property
    def data_value(self) -> PSBytes:
        if self.data is not None:
            return self.data
        elif self.rawdata is not None:
            return self.rawdata
        else:
            raise ValueError(f"PDFObjectStream {self!r} does not have any data")

    def decode(self):
        assert self.data is None \
               and self.rawdata is not None, str((self.data, self.rawdata))
        data = self.rawdata
        if self.decipher:
            # Handle encryption
            assert self.objid is not None
            assert self.genno is not None
            data = self.decipher(self.objid, self.genno, data, self.attrs)
        filters = self.get_filters()
        if not filters:
            self.data = data
            self.rawdata = None
            return
        for (f, params) in filters:
            decoded: Optional[bytes] = None
            if f in LITERALS_FLATE_DECODE:
                # will get errors if the document is encrypted.
                try:
                    decoded = zlib.decompress(data)
                except zlib.error as e:
                    decoded = DecodingError(str(e))
            elif f in LITERALS_LZW_DECODE:
                decoded = lzwdecode(data)
            elif f in LITERALS_ASCII85_DECODE:
                decoded = ascii85decode(data)
            elif f in LITERALS_ASCIIHEX_DECODE:
                decoded = asciihexdecode(data)
            elif f in LITERALS_RUNLENGTH_DECODE:
                decoded = rldecode(data)
            elif f in LITERALS_CCITTFAX_DECODE:
                decoded = ccittfaxdecode(data, params)
            elif f in LITERALS_DCT_DECODE:
                # This is probably a JPG stream
                # it does not need to be decoded twice.
                # Just return the stream to the user.
                pass
            elif f in LITERALS_JBIG2_DECODE:
                pass
            elif f == LITERAL_CRYPT:
                # not yet..
                raise PDFNotImplementedError('/Crypt filter is unsupported')
            else:
                raise PDFNotImplementedError('Unsupported filter: %r' % f)
            if decoded is not None:
                if isinstance(f, PDFLiteral):
                    name = f.name
                else:
                    name = f
                data = PDFStreamFilter(
                    decoded,
                    pdf_offset=data.pdf_offset,
                    pdf_bytes=data.pdf_bytes,
                    original_bytes=data,
                    name=name
                )
            # apply predictors
            if params and 'Predictor' in params:
                pred = int_value(params['Predictor'])
                if pred == 1:
                    # no predictor
                    pass
                elif 10 <= pred:
                    # PNG predictor
                    colors = int_value(params.get('Colors', 1))
                    columns = int_value(params.get('Columns', 1))
                    raw_bits_per_component = params.get('BitsPerComponent', 8)
                    bitspercomponent = int_value(raw_bits_per_component)
                    predicted = apply_png_predictor(pred, colors, columns,
                                               bitspercomponent, data)
                    data = PNGPredictor(
                        predicted,
                        pdf_offset=data.pdf_offset,
                        pdf_bytes=data.pdf_bytes,
                        original_bytes=data,
                        params=params
                    )
                else:
                    error_msg = 'Unsupported predictor: %r' % pred
                    raise PDFNotImplementedError(error_msg)
        self.data = data
        self.rawdata = None
        return


class PDFParser(PDFMinerParser):
    auto_flush: bool = False

    @staticmethod
    def string_escape(data: Union[bytes, int]) -> str:
        if not isinstance(data, int):
            return "".join(PDFParser.string_escape(d) for d in data)
        elif data == ord('\n'):
            return "\\n"
        elif data == ord('\t'):
            return "\\t"
        elif data == ord('\r'):
            return "\\r"
        elif data == 0:
            return "\\0"
        elif data == ord('\\'):
            return "\\\\"
        elif 32 <= data <= 126:
            return chr(data)
        else:
            return f"\\x{data:02X}"

    def token_context(self, token: Union[PDFBaseParserToken, PSStr], padding_bytes: int = 10) -> str:
        pos_before = self.fp.tell()
        try:
            bytes_before = min(token.pdf_offset, padding_bytes)
            self.fp.seek(token.pdf_offset - bytes_before)
            if bytes_before > 0:
                context_before = PDFParser.string_escape(self.fp.read(bytes_before))
            else:
                context_before = ""
            content = PDFParser.string_escape(self.fp.read(token.pdf_bytes))
            context_after = PDFParser.string_escape(self.fp.read(padding_bytes))
            return f"{context_before}{content}{context_after}\n" \
                   f"{' ' * len(context_before)}" \
                   f"{'^' * len(content)}" \
                   f"{' ' * len(context_after)}"
        finally:
            self.fp.seek(pos_before)

    def push(self, *objs: PSStackEntry[ExtraT]):
        transformed = []
        for obj in objs:
            if len(obj) == 2 and isinstance(obj[1], dict):
                length = self._curtokenpos + 1 - obj[0]
                assert length > 0
                transformed.append((obj[0], PDFDict(obj[1], pdf_offset=obj[0], pdf_bytes=length + 2)))
            elif len(obj) == 2 and isinstance(obj[1], list):
                length = self._curtokenpos + 1 - obj[0]
                assert length > 0
                transformed.append((obj[0], PDFList(obj[1], pdf_offset=obj[0], pdf_bytes=length)))
            elif len(obj) == 2 and isinstance(obj[1], PDFStream):
                stream: PDFStream = obj[1]
                pos = obj[0]
                transformed.append((pos, PDFObjectStream(stream, pdf_offset=pos, pdf_bytes=len(stream.rawdata))))
            elif len(obj) == 2 and isinstance(obj[1], PSObject) and not isinstance(obj[1], PDFLiteral):
                pos = obj[0]
                psobj = obj[1]
                length = self._curtokenpos + 1 - obj[0]
                if isinstance(psobj, PDFObjRef):
                    orig_pos = pos
                    pos = min(pos, psobj.objid.pdf_offset)
                    length += orig_pos - pos
                setattr(psobj, "pdf_offset", pos) 
                setattr(psobj, "pdf_bytes", length)
                transformed.append((pos, psobj))
            else:
                transformed.append(obj)
        return super().push(*transformed)

    def _add_token(self, obj: PSBaseParserToken):
        if hasattr(obj, "pdf_offset"):
            pos = obj.pdf_offset
        else:
            pos = self._curtokenpos
        if hasattr(obj, "pdf_bytes"):
            length = obj.pdf_bytes
        elif isinstance(obj, PSLiteral):
            length = len(self._curtoken)
        else:
            length = len(self._curtoken)
        obj = make_ps_object(obj, pdf_offset=pos, pdf_bytes=length)
        # log.info(f"\n{self.token_context(obj)}")
        return super()._add_token(obj)

    def flush(self):
        if self.auto_flush:
            self.add_results(*self.popall())
        else:
            super().flush()

    def do_keyword(self, pos: int, token: PSKeyword):
        if token is self.KEYWORD_R:
            # reference to indirect object
            try:
                ((_, objid), (_, genno)) = self.pop(2)
                obj = PDFObjRef(self.doc, objid, genno)
                self.push((pos, obj))
            except PSSyntaxError:
                pass
        else:
            super().do_keyword(pos, token)

    # def nexttoken(self) -> Tuple[int, PSBaseParserToken]:
    #     pos, token = super().nexttoken()
    #     if isinstance(token, PSObject):
    #         setattr(token, "pdf_offset", pos)
    #     elif isinstance(token, int):
    #         token = PSInt(token, pdf_offset=pos)
    #     elif isinstance(token, bytes):
    #         token = PSBytes(token, pdf_offset=pos)
    #     elif isinstance(token, float):
    #         token = PSFloat(token, pdf_offset=pos)
    #     elif isinstance(token, bool):
    #         token - PSBool(token, pdf_offset=pos)
    #     else:
    #         raise NotImplementedError(f"Add support for tokens of type {type(token)}")
    #     return pos, token

    #def do_keyword(self, pos: int, token: PSKeyword) -> None:


class RawPDFStream:
    def __init__(self, file_stream):
        self._file_stream = file_stream

    def read(self, *args, **kwargs):
        offset_before = self._file_stream.tell()
        ret = self._file_stream.read(*args, **kwargs)
        if isinstance(ret, bytes):
            ret = PSBytes(ret, pdf_offset=offset_before)
        return ret

    def __getattr__(self, item):
        return getattr(self._file_stream, item)


def parse_object(obj, matcher: Matcher, parent=None):
    if isinstance(obj, PDFObjectStream):
        log.status(f"Parsing PDF obj {obj.objid} {obj.genno}")
        if parent is None or isinstance(parent, PDF):
            parent_offset = 0
        else:
            parent_offset = parent.offset
        data = obj.get_data()
        match = Submatch(
            name="PDFObject",
            display_name=f"PDFObject{obj.objid}.{obj.genno}",
            match_obj=(obj.objid, obj.genno),
            relative_offset=obj.attrs.pdf_offset,
            length=obj.data_value.pdf_offset - obj.attrs.pdf_offset + obj.data_value.pdf_bytes,
            parent=parent
        )
        yield match
        yield from parse_object(obj.attrs, matcher=matcher, parent=match)
        yield from parse_object(data, matcher=matcher, parent=match)
        log.clear_status()
    elif isinstance(obj, PDFStreamFilter):
        filter_obj = Submatch(
            f"{obj.name!s}",
            bytes(obj.original_bytes),
            relative_offset=obj.pdf_offset - parent.offset,
            length=obj.pdf_bytes,
            parent=parent
        )
        yield filter_obj
        if obj.error is None:
            yield Submatch(
                "DecodedStream",
                bytes(obj),
                relative_offset=obj.pdf_offset - parent.offset,
                length=obj.pdf_bytes,
                parent=filter_obj,
                decoded=bytes(obj)
            )
        else:
            yield Submatch(
                "DecodingError",
                obj.error.message,
                relative_offset=obj.pdf_offset - parent.offset,
                length=obj.pdf_bytes,
                parent=filter_obj
            )
        yield from parse_object(obj.original_bytes, matcher=matcher, parent=filter_obj)
    elif isinstance(obj, PDFList):
        list_obj = Submatch(
            "PDFList",
            '',
            relative_offset=obj.pdf_offset - parent.offset,
            length=obj.pdf_bytes,
            parent=parent
        )
        yield list_obj
        for item in obj:
            yield from parse_object(item, matcher=matcher, parent=list_obj)
    elif isinstance(obj, PDFDict):
        dict_obj = Submatch(
            "PDFDictionary",
            '',
            relative_offset=obj.pdf_offset - parent.offset,
            length=obj.pdf_bytes,
            parent=parent
        )
        yield dict_obj
        for key, value in obj.items():
            if not hasattr(value, "pdf_offset") or not hasattr(value, "pdf_bytes"):
                if isinstance(value, list):
                    value = PDFList.load(value)
                else:
                    raise ValueError(f"Unexpected PDF dictionary value {value!r}")
            pair = Submatch(
                "KeyValuePair",
                '',
                relative_offset=key.pdf_offset - dict_obj.offset,
                length=value.pdf_offset + value.pdf_bytes - key.pdf_offset,
                parent=dict_obj
            )
            yield pair
            yield Submatch(
                "Key",
                key,
                relative_offset=0,
                length=key.pdf_bytes,
                parent=pair
            )
            value_match = Submatch(
                "Value",
                value,
                relative_offset=value.pdf_offset - key.pdf_offset,
                length=value.pdf_bytes,
                parent=pair
            )
            yield value_match
            yield from parse_object(value, matcher=matcher, parent=value_match)
    elif isinstance(obj, PDFDeciphered):
        deciphered = Submatch(
            "PDFDeciphered",
            obj.original_bytes,
            decoded=obj,
            relative_offset=obj.pdf_offset - parent.offset,
            length=obj.pdf_bytes,
            parent=parent
        )
        yield deciphered
        with Tempfile(obj) as f:
            yield from matcher.match(f, parent=deciphered)
    elif isinstance(obj, PSBytes):
        if isinstance(obj, PNGPredictor):
            match = Submatch(
                "PNGPredictor",
                bytes(obj.original_bytes),
                decoded=obj,
                relative_offset=obj.pdf_offset - parent.offset,
                length=obj.pdf_bytes,
                parent=parent
            )
            yield from parse_object(obj.params, matcher=matcher, parent=match)
            yield from parse_object(obj.original_bytes, matcher=matcher, parent=match)
        else:
            match = Submatch(
                obj.__class__.__name__,
                bytes(obj),
                relative_offset=obj.pdf_offset - parent.offset,
                length=obj.pdf_bytes,
                parent=parent
            )
        if hasattr(obj, "original_bytes"):
            yield from parse_object(obj.original_bytes, matcher=matcher, parent=match)
        # recursively match against the deflated contents
        with Tempfile(obj) as f:
            yield from matcher.match(f, parent=match)
    elif hasattr(obj, "pdf_offset") and hasattr(obj, "pdf_bytes"):
        yield Submatch(
            obj.__class__.__name__,
            obj,
            relative_offset=obj.pdf_offset - parent.offset,
            length=obj.pdf_bytes,
            parent=parent
        )

    # yield Submatch(
    #     "PDFObjectID",
    #     object.id,
    #     relative_offset=0,
    #     length=len(objid.token),
    #     parent=obj
    # )
    # yield Submatch(
    #     "PDFObjectVersion",
    #     object.version,
    #     relative_offset=objversion.offset.offset - objid.offset.offset,
    #     length=len(objversion.token),
    #     parent=obj
    # )

# class NonZeroIndexXRef(PDFXRef):
#     @property
#     def trailer(self) -> :


class InstrumentedPDFDocument(PDFDocument):
    def __init__(self, *args, **kwargs):
        self._xrefs = []
        self._decipher: Optional[DecipherCallable] = None
        super().__init__(*args, **kwargs)

    # @property
    # def xrefs(self):
    #     if not self._xrefs:
    #         pass
    #     return self._xrefs
    #
    # @xrefs.setter
    # def xrefs(self, new_value):
    #     self._xrefs = new_value

    @property
    def decipher(self) -> DecipherCallable:
        if self._decipher is None:
            return None
        else:
            return self.do_decipher

    @decipher.setter
    def decipher(self, new_value: DecipherCallable):
        self._decipher = new_value

    def do_decipher(self, *args, **kwargs) -> PSBytes:
        deciphered = self._decipher(*args, **kwargs)
        if isinstance(deciphered, bytes) and not isinstance(deciphered, PSBytes):
            for arg in args:
                if isinstance(arg, PSBytes):
                    deciphered = PDFDeciphered(
                        deciphered,
                        pdf_offset=arg.pdf_offset,
                        pdf_bytes=arg.pdf_bytes,
                        original_bytes=arg
                    )
                    break
        return deciphered


@submatcher("application/pdf")
class PDF(Match):
    def submatch(self, file_stream):
        # pdfminer expects %PDF to be at byte offset zero in the file
        pdf_header_index = file_stream.first_index_of(b"%PDF")
        if pdf_header_index > 0:
            # the PDF header does not start at byte offset zero!
            with FileStream(file_stream, start=pdf_header_index) as f:
                for match in self.submatch(f):
                    # account for the offset
                    match._offset += pdf_header_index
                    yield match
            return
        parser = PDFParser(RawPDFStream(file_stream))
        doc = InstrumentedPDFDocument(parser)
        yielded = set()
        for xref in doc.xrefs:
            for objid in xref.get_objids():
                try:
                    obj = doc.getobj(objid)
                except PDFObjectNotFound:
                    continue
                if isinstance(obj, PDFObjectStream):
                    if (obj.objid, obj.genno) in yielded:
                        continue
                    yielded.add((obj.objid, obj.genno))
                    yield from parse_object(obj, self.matcher, self)
                else:
                    if objid in yielded or not hasattr(obj, "pdf_offset") or not hasattr(obj, "pdf_bytes"):
                        continue
                    yielded.add(objid)
                    match = Submatch(
                        name="PDFObject",
                        display_name=f"PDFObject{objid}",
                        match_obj=objid,
                        relative_offset=obj.pdf_offset,
                        length=obj.pdf_bytes,
                        parent=self
                    )
                    yield from parse_object(obj, self.matcher, match)
        #yield from parse_pdf(file_stream, matcher=self.matcher, parent=self)
