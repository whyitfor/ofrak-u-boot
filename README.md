# ofrak-u-boot

## Build image
Setup and emulation steps here are based on [Pandy's Blog](https://pandysong.github.io/blog/post/run_u-boot_in_qemu/), with minor updates for clarity.
YMMV.

To build the u-boot, run:

```
git clone https://github.com/ARM-software/u-boot.git
cd u-boot/
export CROSS_COMPILE=arm-linux-gnueabi-
make qemu_arm_defconfig
make
```

## Emulate
To emulate the image, run:

```
qemu-system-arm -curses -machine virt -bios u-boot.bin
```

`Esc + 1` can be used to go to `qemu monitor command interface`.
`Esc + 2` can be used to view the u-boot interface.
To quit, run `quit` from the qemu monitor interface.