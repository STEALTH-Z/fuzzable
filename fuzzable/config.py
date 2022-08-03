"""
config.py

    Defines configuration knobs that can be universally configured by
    any fuzzable client
"""
import typing as t

from os.path import dirname, abspath

# Top level directory for project
ROOT_DIR = dirname(dirname(abspath(__file__)))

# Supported source code paths
# TODO: we should do a very initial parse on the file to determine if it is C++ source
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".cp" ".cxx", ".h", ".hpp", ".hh"]

# Source file patterns to ignore unless turned off
SOURCE_IGNORE: t.List[str] = ["test", "example"]

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

# Function name patterns that include known
FALSE_POSITIVE_SIMILARS: t.List[str] = [
    # str
    "destroy"
]

# Data sink call names that should be deemed risky
# TODO: dataset of risky function calls
RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "alloc",
    "create",
]

SETTINGS = {}
