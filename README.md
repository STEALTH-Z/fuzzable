# Fuzzable

![ci](https://github.com/ex0dus-0x/fuzzable/actions/workflows/main.yml/badge.svg)

Framework for Automating _Fuzzable_ Target Discovery with Static Analysis

![example](/extras/cli.png "CLI Example")

## Introduction

Vulnerability researchers conducting security assessments on software will often harness the capabilities of coverage-guided fuzzing through powerful tools like AFL++ and libFuzzer. This is important as it automates the bughunting process and reveals exploitable conditions in targets quickly. However, when encountering large and complex codebases or closed-source binaries, researchers have to painstakingly dedicate time to manually audit and reverse engineer them to identify functions where fuzzing-based exploration can be useful.

__Fuzzable__ is a framework that integrates both with C/C++ source code and binaries to assist vulnerability researchers in identifying function targets that are viable for fuzzing. This is done by applying several static analysis-based heuristics to pinpoint risky behaviors in the software and the functions that executes them. Researchers can then utilize the framework to generate basic harness templates, which can then be used to hunt for vulnerabilities, or to be integrated as part of a continuous fuzzing pipeline, such as Google's oss-fuzz.

In addition to running as a standalone tool, Fuzzable is also integrated as a plugin for Binary Ninja, with support for other disassembly backends being developed.

Check out the very original blog post detailing the plugin [here](https://codemuch.tech/2021/06/07/fuzzabble/). This tool will also be featured at [Blackhat Arsenal USA 2022](https://www.blackhat.com/us-22/arsenal/schedule/index.html#automating-fuzzable-target-discovery-with-static-analysis-26726).

## Features

* Supports analyzing __binaries__ (with [Angr](https://angr.io) and [Binary Ninja](https://binary.ninja)) and
__source code__ artifacts (with [tree-sitter](https://tree-sitter.github.io/tree-sitter/)).
* Run static analysis both as a __standalone CLI tool__ or a __Binary Ninja plugin__.
* __Harness generation__ to ramp up on creating fuzzing campaigns quickly.

## Usage

Some binary targets may require some sanitizing (ie. signature matching, or identifying functions from inlining), and therefore 
__fuzzable__ primarily uses Binary Ninja as a disassembly backend because of it's ability to effectively solve these problems. Therefore, it can be utilized both as a standalone tool and plugin.

Since Binary Ninja isn't accessible to all and there may be a demand to utilize for security assessments and potentially scaling up in the cloud, an [angr](https://github.com/angr/angr)
_fallback_ backend is also supported. I anticipate to incorporate other disassemblers down the road as well (priority: Ghidra).

### Command Line (Standalone)

If you have Binary Ninja Commercial , be sure to install the API for standalone headless usage:

```
$ python3 /Applications/Binary\ Ninja.app/Contents/Resources/scripts/install_api.py
```

Now install `fuzzable` with `pip`:

```
$ pip install fuzzable
```

You can now analyze binaries and/or source code with the tool!

```
# analyzing a single shared object library binary
$ fuzzable analyze examples/binaries/libsimple.so.1

# analyzing a single C source file
$ fuzzable analyze examples/source/libsimple.c

# analyzing a workspace with multiple C/C++ files and headers
$ fuzzable analyze examples/source/source_bundle/
```

### Binary Ninja Plugin

__fuzzable__ can be easily installed through the Binary Ninja plugin marketplace by going to `Binary Ninja > Manage Plugins` and searching for it. Here is an example of the __fuzzable__ plugin running on [cesanta/mjs](https://github.com/cesanta/mjs),
accuracy identifying targets for fuzzing and further vulnerability assessment:

![binja_example](/extras/binja_example.png "Binary Ninja Example")

### Manual / Development

We use [poetry](https://python-poetry.org) for dependency management. To do a manual build, clone the repository with the third-party modules:

```
$ git clone --recursive https://github.com/ex0dus-0x/fuzzable
```

To install manually:

```
$ cd fuzzable/

# without poetry
$ pip install .

# with poetry
$ poetry install

# with poetry for a development virtualenv
$ poetry shell
```

## Settings

By default, __fuzzable__ will attempt to make intelligent decisions on which functions it should present
back to you, and thus will ignore calls from analysis and showing up in the report.

Given how diverse binaries are, the plugin provides several settings one may choose to tweak for different targets:

* `depth_threshold`

Minimum number of levels in callgraph to be considered optimal for fuzzing.

Functions that automatically have a callgraph depth of >100 will be marked as fuzzable. However, this may be unnecessary in smaller/less
complex binaries, or those that employing inlining.

* `loop_increase_score`

Don't include natural loop as part of the fuzzability score.

The presence of natural loops are incorporated as part of the fuzzability score, since they may denote some form of scanning/parsing
behavior that is worthy to analyze. Turn off if it generates a lot of false positives.

* `skip_stripped`

Ignore including functions that are stripped as part of the final results.

## License

Fuzzable is licensed under the [MIT License](https://codemuch.tech/license.txt).