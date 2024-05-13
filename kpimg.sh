export TARGET_COMPILE=`pwd`/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
cd kernel
# make
# mv kpimg kpimg-linux
# mv kpimg.elf kpimg.elf-linux
make clean
export ANDROID=1
bear -- make DEBUG=1
mv kpimg kpimg-android
mv kpimg.elf kpimg.elf-android
cp -f kpimg-android /www/kpimg-android

cd ..
cd kpms

cd demo-hello
make
mv hello.kpm demo-hello.kpm

cd ../demo-inlinehook
make
mv inlinehook.kpm demo-inlinehook.kpm

cd ../demo-syscallhook
make
mv syscallhook.kpm demo-syscallhook.kpm