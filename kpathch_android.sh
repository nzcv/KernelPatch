export ANDROID=1
mkdir -p tools/build && cd tools/build
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
-DCMAKE_BUILD_TYPE=Release \
-DANDROID_PLATFORM=android-31 \
-DANDROID_ABI=arm64-v8a ..
cmake --build .
cp -f kptools /www/kptools-android

cd  /share/APatch && ./gradlew build -x lint