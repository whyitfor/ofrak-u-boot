import argparse

from ofrak import OFRAK
from ofrak import OFRAKContext
from ofrak.core import *
from ofrak_ghidra.ghidra_model import GhidraProject
from ofrak_ghidra.components.ghidra_analyzer import (
    GhidraProjectConfig,
    GhidraProjectAnalyzer,
)
from ofrak_ghidra.components.blocks.unpackers import GhidraCodeRegionUnpacker


async def main(ofrak_context: OFRAKContext):
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="assets/u-boot.bin")
    parser.add_argument("--gzf", default="assets/u-boot.bin.gzf")
    args = parser.parse_args()
    resource = await ofrak_context.create_root_resource_from_file(args.file)
    program_attributes = ProgramAttributes(
        InstructionSet.ARM,
        bit_width=BitWidth.BIT_32,
        endianness=Endianness.LITTLE_ENDIAN,
        sub_isa=None,
        processor=None,
    )
    resource.add_attributes(program_attributes)
    await resource.save()
    resource.add_tag(GhidraProject)
    await resource.save()
    config = GhidraProjectConfig(
        ghidra_zip_file=args.gzf, name="ghidra_project", use_existing=True
    )
    await resource.run(GhidraProjectAnalyzer, config=config)
    data_length = await resource.get_data_length()
    resource.add_view(
        CodeRegion(
            virtual_address=0,
            size=data_length,
        )
    )
    await resource.save()
    await resource.run(GhidraCodeRegionUnpacker)
    cbs = await resource.get_descendants_as_view(
        v_type=ComplexBlock, r_filter=ResourceFilter(tags=(ComplexBlock,))
    )
    import ipdb

    ipdb.set_trace()
    version_block = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=(ComplexBlock,),
            attribute_filters=[
                ResourceAttributeValueFilter(
                    attribute=ComplexBlock.Symbol, value="do_version"
                )
            ],
        ),
    )
    printf_block = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=(ComplexBlock,),
            attribute_filters=[
                ResourceAttributeValueFilter(
                    attribute=ComplexBlock.Symbol, value="printf"
                )
            ],
        ),
    )
    help_block = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=(ComplexBlock,),
            attribute_filters=[
                ResourceAttributeValueFilter(
                    attribute=ComplexBlock.Symbol, value="do_help"
                )
            ],
        ),
    )
    resource.add_tag(Program)
    await resource.save()
    program = await resource.view_as(Program)
    symbols = {}
    symbols[version_block.name] = (
        version_block.virtual_address,
        LinkableSymbolType.FUNC,
    )
    await program.define_linkable_symbols(symbols)


if __name__ == "__main__":
    o = OFRAK(logging_level=5)
    import ofrak_ghidra

    o.discover(ofrak_ghidra)
    o.run(main)
