#!/bin/sh

# 下载源码
rm libxslt -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/libxslt.git

# 切换到对应commit
cd libxslt
git checkout cdaa67dbb23a867a482add23f2c82062620a95e9
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-ifm_libgcrypt-instead-of-gcrypt.patch ./
patch -i ../libxslt-support-ifm_libgcrypt-instead-of-libgcrypt-spec.patch -p1 < libxslt.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y libxslt.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba libxslt.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build libxslt successful. rpmfile is in /root/rpmbuild/RPMS/"
