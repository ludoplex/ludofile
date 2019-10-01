# PolyFile
<p align="center">
  <img src="logo/polyfile.png?raw=true" width="256" title="PolyFile">
</p>
<br />

A utility to identify and map the semantic structure of files, including polyglots, chimeras, and schizophrenic files.

## Quickstart

In the same directory as this README, run:
```
pip3 install -e .
```

This will automatically install the `polyfile` executable in your path.

## Usage

```
$ polyfile --help
usage: polyfile [-h] [--html HTML] [--debug] [--quiet] FILE

A utility to recursively map the structure of a file.

positional arguments:
  FILE                  The file to analyze

optional arguments:
  -h, --help            show this help message and exit
  --html HTML, -t HTML  Path to write an interactive HTML file for exploring
                        the PDF
  --debug, -d           Print debug information
  --quiet, -q           Suppress all log output (overrides --debug)
```

To generate a JSON mapping of a file, run:

```
polyfile INPUT_FILE > output.json
```

You can optionally have PolyFile output an interactive HTML page containing a labeled hexdump of the file:
```
polyfile INPUT_FILE --html output.html > output.json
```

## License and Acknowledgements

This research was developed by [Trail of
Bits](https://www.trailofbits.com/) with funding from the Defense
Advanced Research Projects Agency (DARPA) under the SafeDocs program
as a subcontractor to [Galois](https://galois.com). This code is in
the process of being open-sourced with the goal of distribution under
an Apache license. However, until that happens, it is only to be used
and distributed under the cooperative agreement between SafeDocs
performers. © 2019, Trail of Bits.
