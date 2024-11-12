import argparse

from ofrak import OFRAK
from ofrak import OFRAKContext
from ofrak.core import *
from ofrak_ghidra.ghidra_model import GhidraProject
from ofrak_ghidra.components.ghidra_analyzer import (
    GhidraProjectConfig,
    GhidraProjectAnalyzer,
)
from ofrak_patch_maker.toolchain.gnu_arm import GNU_ARM_NONE_EABI_10_2_1_Toolchain
from ofrak_patch_maker.toolchain.model import BinFileType, CompilerOptimizationLevel, Segment, ToolchainConfig
from ofrak_ghidra.components.blocks.unpackers import GhidraCodeRegionUnpacker


async def main(
    ofrak_context: OFRAKContext,
    u_boot_path: str,
    u_boot_gzf: str,
):
    resource = await ofrak_context.create_root_resource_from_file(u_boot_path)
    # 1. Add program attributes.
    program_attributes = ProgramAttributes(
        InstructionSet.ARM,
        bit_width=BitWidth.BIT_32,
        endianness=Endianness.LITTLE_ENDIAN,
        sub_isa=None,
        processor=None,
    )
    resource.add_attributes(program_attributes)
    await resource.save()

    # 2. Add pre-analyzed Ghidra Project.
    resource.add_tag(GhidraProject)
    await resource.save()
    config = GhidraProjectConfig(
        ghidra_zip_file=u_boot_gzf, name="ghidra_project", use_existing=True
    )
    await resource.run(GhidraProjectAnalyzer, config=config)

    # 3. Extend the binary to create new RO data section.
    BUFFER_LENGTH = 0x1000
    NEW_RODATA_LENGTH = 0x1000
    EXTEND_LENGTH = BUFFER_LENGTH + NEW_RODATA_LENGTH

    original_length = await resource.get_data_length()
    extend_config = BinaryExtendConfig(b"\x00" * EXTEND_LENGTH)
    await resource.run(BinaryExtendModifier, extend_config)
    new_length = await resource.get_data_length()
    # 4. Add a CodeRegion tag to the whole binary this enables
    #  Ghidra to unpack complex blocks
    resource.add_view(
        CodeRegion(
            virtual_address=0,
            size=new_length,
        )
    )
    await resource.save()

    # 5. Get complex blocks our program references.
    #   Here we only get the blocks we know we need that we have labeled in the Ghidra project.
    resource.add_tag(Program)
    await resource.save()
    await resource.run(GhidraCodeRegionUnpacker)
    program = await resource.view_as(Program)
    version_block = await program.get_function_complex_block("do_version")
    printf_block = await program.get_function_complex_block("printf")
    help_block = await program.get_function_complex_block("do_help")

    # 6. Add these blocks as linkable symbols to the binary.
    #  The PatchFromSourceModifier will find the address of printf via these linkable symbols.
    symbols = {}
    for block in (version_block, printf_block, help_block):
        symbols[block.name] = (block.virtual_address, LinkableSymbolType.FUNC,)
    await program.define_linkable_symbols(symbols)

    # 7. Let the patching begin! Define the segments we will be injecting our code into
    # 7.1 "do_version" will use the existing function and extended spaces for RO data
    version_block_segment = Segment(
        segment_name=".text",
        vm_address=version_block.virtual_address,
        offset=0,
        is_entry=True,
        length=version_block.size // 2,
        access_perms=MemoryPermissions.RX,
    )
    ro_data_segment = Segment(
        segment_name=".rodata",
        vm_address=original_length + BUFFER_LENGTH,
        offset=0,
        is_entry=False,
        length=NEW_RODATA_LENGTH,
        access_perms=MemoryPermissions.R,
    )
    # 7.2 "do_help" will use the existing function
    help_segment_block = Segment(
        segment_name=".text",
        vm_address=help_block.virtual_address,
        offset=0,
        is_entry=True,
        length=version_block.size,
        access_perms=MemoryPermissions.RX,
    )

    # 8. Map source files to where they will be injected.
    source_patches = {
        os.path.abspath("src/do_version.c"): (version_block_segment, ro_data_segment),
        # Pick one of the two implementations of "do_help", comment the other one out
        # os.path.abspath("src/do_help.S"): (help_segment_block,),
        os.path.abspath("src/do_help.c"): (help_segment_block,),
    }

    # 9. Run the PatchFromSourceModifier
    patch_from_source_config = PatchFromSourceModifierConfig(
        source_code=SourceBundle.slurp(os.path.abspath("src")),
        source_patches=source_patches,
        toolchain_config=ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=False,
            relocatable=False,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            create_map_files=True,
            compiler_optimization_level=CompilerOptimizationLevel.SPACE,
            debug_info=False,
            check_overlap=False
        ),
        toolchain=GNU_ARM_NONE_EABI_10_2_1_Toolchain,
        patch_name="do_version_patch",
    )
    await program.resource.run(
        PatchFromSourceModifier, patch_from_source_config
    )

    # 10. Flush modified resource to disk
    await resource.flush_data_to_disk("u-boot.bin.PATCHED")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="assets/u-boot.bin")
    parser.add_argument("--gzf", default="assets/u-boot.bin.gzf")
    args = parser.parse_args()

    o = OFRAK()
    import ofrak_ghidra
    o.discover(ofrak_ghidra)
    o.run(main, args.file, args.gzf)