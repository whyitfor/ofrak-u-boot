# ofrak-u-boot

To build the u-boot, run:

```
git clone https://github.com/ARM-software/u-boot.git
cd u-boot/
export CROSS_COMPILE=arm-linux-gnueabi-
make qemu_arm_defconfig
make
```