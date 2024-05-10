# IDA Graphviz Export

A very simple plugin for converting a function's CFG in IDA to Graphviz code.

## Installation

Run `make install` (assuming you are on macOS or Linux), or otherwise place the
`graphviz.py` file in your IDA user plugins folder.

## Usage

Graphviz code for a function's CFG can be obtained in one of two ways:

1. Use the _Create Graphviz DOT file_ action under the _File > Produce file_ menu.
2. Use the _Dump Graphviz DOT code_ action via the command palette.

## License

BSD 3-Clause; see [LICENSE.txt](LICENSE.txt) for full details.
