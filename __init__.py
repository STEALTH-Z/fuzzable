#!/usr/bin/env python3
"""
__init__.py

    Plugin module used for Binary Ninja
"""
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings

from .fuzzable.analysis import binja

# configurable settings to tune
Settings().register_group("fuzzable", "Fuzzable")
Settings().register_setting(
    "fuzzable.depth_threshold",
    """
    {
        "title"         : "Callgraph depth threshold",
        "description"   : "Minimum number of levels in callgraph to be considered optimal for fuzzing.",
        "type"          : "string",
        "default"       : "100"
    }
""",
)

PluginCommand.register(
    "Fuzzable\\Analysis Mode\\Recommend Fuzzable Functions (much faster)",
    "List out functions we've determined to be the best candidates for fuzzing."
    "This will exclude functions that is determined to not be directly usable for a harness.",
    binja.run_fuzzable_recommend,
)

PluginCommand.register(
    "Fuzzable\\Analysis Mode\\Rank All Function by Fuzzability (more comprehensive)",
    "Generate fuzzability scores for all functions and rank. This will not exclude any function.",
    binja.run_fuzzable_rank,
)

PluginCommand.register(
    "Fuzzable\\Export Fuzzability Report\\CSV (.csv)",
    "Identify and generate targets for fuzzing",
    binja.run_export_csv,
)

PluginCommand.register(
    "Fuzzable\\Export Fuzzability Report\\ Markdown (.md)",
    "Identify and generate targets for fuzzing",
    binja.run_export_md,
)

PluginCommand.register_for_function(
    "Fuzzable\\Harness Generation\\Generate binary fuzzing harness (C/C++ ONLY)",
    "For a target function, generate a AFL-QEMU/libFuzzer C++ harness",
    binja.run_harness_generation,
)
