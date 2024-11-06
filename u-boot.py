import argparse

from ofrak import OFRAK
from ofrak import OFRAKContext
from ofrak.core import *
from ofrak_ghidra.ghidra_model import GhidraProject
from ofrak_ghidra.components.ghidra_analyzer import (
    GhidraProjectConfig,
    GhidraProjectAnalyzer,
)


async def main(ofrak_context: OFRAKContext, file: str, ghidra_project: str):
    resource = await ofrak_context.create_root_resource_from_file(file)

    await resource.flush_data_to_disk(f"{file}.modified")
    program_attributes = ProgramAttributes(
        InstructionSet.ARM,
        bit_width=BitWidth.BIT_32,
        endianness=Endianness.LITTLE_ENDIAN,
    )
    resource.add_attributes(program_attributes)
    await resource.save()
    resource.add_tag(GhidraProject)
    await resource.save()
    config = GhidraProjectConfig(
        ghidra_zip_file=ghidra_project, name="ghidra_project", use_existing=True
    )
    await resource.run(GhidraProjectAnalyzer, config=config)
    complex_blocks = await resource.get_descendants_as_view(
        v_type=ComplexBlock, r_filter=ResourceFilter(tags=(ComplexBlock,))
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="assets/u-boot.bin")
    parser.add_argument("--gzf", default="assets/u-boot.bin.gzf")
    args = parser.parse_args()

    o = OFRAK()
    import ofrak_ghidra

    o.discover(ofrak_ghidra)
    o.run(main)
