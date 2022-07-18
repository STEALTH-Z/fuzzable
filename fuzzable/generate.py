"""
generate.py

    Creates template harnesses for a given target.
"""
import os
import typing as t

import lief
from lief import ELF

from pathlib import Path


def transform_elf_to_so(
    path: Path, lib: lief.Binary, exports: t.List[str], override_path: t.Optional[str]
) -> t.Optional[str]:
    """
    Uses LIEF to check if an ELF executable can be transformed into a shared object with exported
    symbols for fuzzing.
    """

    # check if shared object or PIE binary
    # TODO: stronger checks for shared object
    if lib.header.file_type is not ELF.E_TYPE.DYNAMIC and not ".so" in path.suffix:
        return None

    for sym in exports:
        addr = lief.get_function_address(sym)
        lib.add_exported_function(addr, sym)

    if not override_path:
        lib.write(path + "_exported.so")
    else:
        lib.write(override_path)

    return path + "_exported.so"


def generate_harness(
    target_name: str,
    function_name: str,
    return_type: str,
    params: t.List[str],
    harness_path: t.Optional[str] = str,
    output: t.Optional[str] = None,
) -> None:
    """ """
    template_path = Path("templates" / "linux_closed_source_harness.cpp")
    if harness_path:
        template_path = harness_path

    with open(template_path, "r") as fd:
        template = fd.read()

    template = template.replace("{NAME}", os.path.basename(target_name))
    template = template.replace("{function_name}", function_name)
    template = template.replace("{return_type}", return_type)
    template = template.replace("{type_args}", params)

    harness = f"{target_name}_{function_name}_harness.cpp"
    if output is not None:
        harness = output

    with open(harness) as fd:
        fd.write(template)
