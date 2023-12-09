#!/bin/sh

# 下载源码
rm gnutls -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/gnutls.git

# 切换到对应commit
cd gnutls
git checkout d05745a6ae13fa9316a8116853e670543f1350d7
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-ifm_nettle-instead-of-nettle.patch ./
patch -i ../gnutls-support-ifm_nettle-instead-of-nettle-spec.patch -p1 < gnutls.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y gnutls.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba gnutls.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build gnutls successful. rpmfile is in /root/rpmbuild/RPMS/"
