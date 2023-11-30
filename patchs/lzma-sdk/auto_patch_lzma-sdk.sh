#!/bin/sh

# 下载源码
rm LZMA-SDK -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/LZMA-SDK.git

# 切换到对应commit
cd LZMA-SDK
git checkout f86ea60afe698e5f99176c28ff4f62ae4768a8ea
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../build-the-7lzma-lib.patch ./
patch -i ../LZMA-SDK-spec.patch -p1 < LZMA-SDK.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y LZMA-SDK.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba LZMA-SDK.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build LZMA-SDK successful. rpmfile is in /root/rpmbuild/RPMS/"
