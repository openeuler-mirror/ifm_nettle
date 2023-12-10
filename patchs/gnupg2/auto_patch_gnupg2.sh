#!/bin/sh

# 下载源码
rm gnupg2 -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/gnupg2.git

# 切换到对应commit
cd gnupg2
git checkout d215d0e23ec9f5badc542c56bcc5e244774cd212
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-ifm-gcrypt-instead-of-gcrypt-in-gnupg2.patch ./
patch -i ../support-ifm_gcrypt-in-gnupg-spec.patch -p1 < gnupg2.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y gnupg2.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba gnupg2.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build gnupg2 successful. rpmfile is in /root/rpmbuild/RPMS/"
