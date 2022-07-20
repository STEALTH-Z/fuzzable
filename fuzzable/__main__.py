#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import logging
import typing as t
import typer
import lief

from rich import print

from fuzzable import generate
from fuzzable.config import SOURCE_FILE_EXTS, SOURCE_IGNORE
from fuzzable.cli import print_table, error
from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.log import log

from pathlib import Path

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def analyze(
    target: Path,
    mode: t.Optional[str] = typer.Option(
        "recommend",
        help="Analysis mode to run under (either `recommend` or `rank`, default is `recommend`)."
        "See documentation for more details about which to select.",
    ),
    export: t.Optional[str] = typer.Option(
        None,
        help="Export the fuzzability report based on the file extension."
        "Fuzzable supports either a raw CSV (.csv) file or Markdown.",
    ),
    list_ignored: bool = typer.Option(
        False,
        help="If set, will also additionally output or export ignored symbols.",
    ),
    debug: bool = typer.Option(
        False,
        help="If set, will be verbose and output debug information.",
    ),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a compiled binary.
    """
    if debug:
        log.setLevel(logging.DEBUG)

    try:
        mode = AnalysisMode[mode.upper()]
    except Exception:
        error(f"Invalid analysis mode `{mode}`. Must either be `recommend` or `rank`.")

    log.info(f"Starting fuzzable on {target}")
    if target.is_file():
        run_on_file(target, mode, export)
    elif target.is_dir():
        run_on_workspace(target, mode, export)
    else:
        error(f"Target path `{target}` does not exist")


def run_on_file(target: Path, mode: AnalysisMode, export: t.Optional[Path]) -> None:
    """Runs analysis on a single source code file or binary file."""
    analyzer: t.TypeVar[AnalysisBackend]
    if target.suffix in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis([target], mode)
    else:

        # prioritize loading binja as a backend, this may not
        # work if the license is personal/student.
        try:
            from binaryninja.binaryview import BinaryViewType
            from fuzzable.analysis.binja import BinjaAnalysis

            bv = BinaryViewType.get_view_of_file(target)
            bv.update_analysis_and_wait()
            analyzer = BinjaAnalysis(bv, mode, headless=True)

        # didn't work, try to load angr as a fallback instead
        except Exception:
            log.warning(
                f"Cannot load Binary Ninja as a backend. Attempting to load angr instead."
            )
            try:
                import angr
                from fuzzable.analysis.angr import AngrAnalysis

                proj = angr.Project(target, load_options={"auto_load_libs": False})
                analyzer = AngrAnalysis(proj, mode)
            except Exception as err:
                error(f"Unsupported target {target}. Reason: {err}")

    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped)


def run_on_workspace(
    target: Path, mode: AnalysisMode, export: t.Optional[Path]
) -> None:
    """
    Given a workspace, recursively iterate and parse out all of the source code files
    that are present. This is not currently supported on workspaces of binaries/libraries.
    """
    source_files = []
    for subdir, _, files in os.walk(target):
        for file in files:
            if Path(file).suffix in SOURCE_FILE_EXTS:
                log.info(f"Adding {file} to set of source code to analyze")
                source_files += [Path(os.path.join(subdir, file))]

    if len(source_files) == 0:
        error(
            "No C/C++ source code found in the workspace. fuzzable currently does not support parsing on workspaces with multiple binaries."
        )

    analyzer = AstAnalysis(source_files, mode)
    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped)


@app.command()
def create_harness(
    target: str,
    symbol_name: str = typer.Option(
        "",
        help="Names of function symbol to create a fuzzing harness to target. Source not supported yet.",
    ),
    out_so_name: t.Optional[str] = typer.Option(
        None, help="Specify to set output `.so` path of a transformed ELF binary."
    ),
    out_harness: t.Optional[str] = typer.Option(
        None, help="Specify to set output harness template file path."
    ),
    file_fuzzing: bool = typer.Option(
        False,
        help="If enabled, will generate a harness that takes a filename parameter instead of reading from STDIN.",
    ),
    libfuzzer: bool = typer.Option(
        False,
        help="If enabled, will set the flag that compiles the harness as a libFuzzer harness instead of for AFL.",
    ),
):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a binary target (TODO: source)."""
    if not symbol_name:
        error("No --symbol_name specified.")

    # if a binary, check if executable or library. if executable, use LIEF to
    # copy, export the symbol and transform to shared object.
    binary = lief.parse(target)
    if binary is None:
        error(
            "Wrong filetype, or does not support synthesizing harnesses for C/C++ source code yet."
        )

    target = Path(target)
    log.info(f"Running harness generation for `{target}` on symbol `{symbol_name}`.")
    shared_obj = generate.transform_elf_to_so(target, binary, symbol_name, out_so_name)

    generate.generate_harness(shared_obj, symbol_name, harness_path=out_harness)
    log.info("Done!")


# TOOD list-functions
# TODO generate-callgraph
# TODO reference-cve
