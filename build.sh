#!/bin/sh

rm -rf build/
mkdir build
cd build
cmake .. -DLIB_INSTALL_DIR=/usr/lib64
if [ $? -ne 0 ];then
    echo "Failed: cmake failed, exit"
    exit 1
fi
make
if [ $? -ne 0 ];then
    echo "Failed: make failed, exit"
    exit 1
fi

ctest
if [ $? -ne 0 ];then
    echo "Failed: ctest failed, exit"
    exit 1
fi

echo "SUCCESS: Build ifm_nettle successful."

if [ x$1 == x"install" ]; then
    make install
    echo "SUCCESS: install ifm_nettle successful."
fi
