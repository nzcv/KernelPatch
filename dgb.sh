cp ~/Documents/KernelPatchQEMU/arch/arm64/boot/Image .
./kptools-linux -p -i Image -S a12345678 -k kernel/kpimg -o ~/Documents/KernelPatchQEMU/arch/arm64/boot/Image2 -K kpatch-android
# qemu-system-aarch64  -M virt -cpu cortex-a57 -smp 1 -m 1G  -kernel Image  -nographic  \
# -append "console=ttyAMA0 oops=panic panic_on_warn=1 panic=-1 ftrace_dump_on_oops=orig_cpu debug earlyprintk=serial slub_debug=UZ root=/dev/ram rdinit=/bin/sh" \
# -initrd rootfs.img -S -gdb tcp::9000