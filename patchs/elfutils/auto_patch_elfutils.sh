#!/bin/sh

# 下载源码
rm elfutils -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/elfutils.git

# 切换到对应commit
cd elfutils
git checkout e352a14e9b6555f94f79bb0e260f577b646d9dcd
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-unizip-instead-of-zlib.patch ./
patch -i ../elfutils-support-unizip-instead-of-zlib-spec.patch -p1 < elfutils.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y elfutils.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba elfutils.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build elfutils successful. rpmfile is in /root/rpmbuild/RPMS/"
