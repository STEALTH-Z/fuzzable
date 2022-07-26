"""
generate.py

    Creates template harnesses for a given target.
"""
import os
import typing as t

import lief
from lief import ELF

from pathlib import Path

from .log import log


def generate_harness(
    target_name: str,
    function_name: str,
    return_type: t.Optional[str] = None,
    params: t.Optional[t.List[str]] = None,
    harness_path: t.Optional[str] = None,
    output: t.Optional[str] = None,
) -> None:
    """
    Populate a harness template with given parameters and generate harness to path.
    """
    template_path = Path("templates") / "linux_closed_source_harness.cpp"
    if harness_path:
        template_path = harness_path

    log.debug("Reading harness template")
    with open(template_path, "r", encoding="utf-8") as template_file:
        template = template_file.read()

    log.debug("Replacing parameters in template")
    name = os.path.basename(target_name).split(".")[0]
    template = template.replace("{NAME}", os.path.basename(target_name))
    template = template.replace("{function_name}", function_name)

    # these are optional and can be populated by the user
    if return_type:
        template = template.replace("{return_type}", return_type)
    if params:
        if len(params) != 0:
            template = template.replace("{type_args}", params)

    harness = f"{name}_{function_name}_harness.cpp"
    if output is not None:
        harness = output

    log.debug(f"Writing harness to path {harness}")
    with open(harness, "w", encoding="utf-8") as template_file:
        template_file.write(template)


def transform_elf_to_so(
    path: Path, lib: lief.Binary, exports: t.List[str], override_path: t.Optional[Path]
) -> t.Optional[Path]:
    """
    Helper that uses LIEF to check if an ELF executable can be transformed into a shared object
    with exported symbols for fuzzing.
    """

    # check if shared object or PIE binary
    # TODO: stronger checks for shared object
    if lib.header.file_type is not ELF.E_TYPE.DYNAMIC and ".so" in path.suffix:
        log.info("No need to transform binary into a shared object")
        return path

    for sym in exports:
        addr = lib.get_function_address(sym)
        lib.add_exported_function(addr)

    path = str(path) + "_exported.so"
    if override_path:
        path = str(override_path)

    log.info(
        "Transforming the ELF binary into a shared object for harness genaration at {path}"
    )
    lib.write(path)
    return Path(path)
