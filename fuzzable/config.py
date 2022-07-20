"""
config.py

    Defines configuration knobs that can be universally configured by
    any fuzzable client
"""
import typing as t

# Supported source code paths
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp", ".hh"]

# Source file patterns to ignore
SOURCE_IGNORE = ["test", "example"]

# Interesting symbol name patterns to check for fuzzable
INTERESTING_PATTERNS: t.List[str] = [
    # Consuming Inputs
    "parse",
    "read",
    "buf",
    "file",
    "input",
    "str",
    # Decryption Routines
    "encode",
    "decode",
]

# TODO make this better
FALSE_POSITIVE_SIMILARS: t.List[str] = [
    # str
    "destroy"
]

# TODO: dataset of risky function calls
RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "free",
    "alloc",
    "create",
]

SETTINGS = {}
