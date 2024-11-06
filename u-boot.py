import argparse

from ofrak import OFRAK
from ofrak import OFRAKContext
async def main(ofrak_context: OFRAKContext, file: str, ghidra_project: str)
    resource = await ofrak_context.create_root_resource_from_file(file)

    await resource.flush_data_to_disk(f"{file}.modified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="assets/u-boot.bin")
    parser.add_argument("--gzf", default="assets/u-boot.bin.gzf")
    args = parser.parse_args()

    o = OFRAK()
    import ofrak_ghidra
    o.discover(ofrak_ghidra)
    o.run(main)