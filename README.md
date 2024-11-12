# ofrak-u-boot
This repository shows strategies for using OFRAK to patch raw binary files.

## Using `PatchFromSourceModifier`
The file `u-boot-patch-commands.py` is an example of patching the u-boot.bin binary.
It does the following:

1. Extends binary to create a new RO_DATA segment
2. Patches the u-boot `version` command such that it returns `Meow!`
3. Patches the u-boot `help` command such that it calls `version` instead.

To try it out, run:

Run:
```bash
python3 u-boot-patch-commands.py
```

## Build u-boot image
Setup and emulation steps here are based on [Pandy's Blog](https://pandysong.github.io/blog/post/run_u-boot_in_qemu/), with minor updates for clarity.
YMMV.

The u-boot asset was build using the following:
```
git clone https://github.com/ARM-software/u-boot.git
cd u-boot/
export CROSS_COMPILE=arm-linux-gnueabi-
make qemu_arm_defconfig
make
```

## Emulate
To emulate the image (or the patched image), run:

```
qemu-system-arm -curses -machine virt -bios u-boot.bin
```

`Esc + 1` can be used to go to `qemu monitor command interface`.
`Esc + 2` can be used to view the u-boot interface.
To quit, run `quit` from the qemu monitor interface.
