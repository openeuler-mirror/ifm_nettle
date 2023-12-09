#!/bin/sh

# 下载源码
rm libiscsi -rf
git clone https://gitee.com/src-openeuler/libiscsi.git

# 切换到对应commit
cd libiscsi
git checkout 22a4ef66b7c036720e37d0ca0c5893c94babd4a9
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../0024-support-ifm_libgcrypt-instead-of-libgcrypt.patch ./
patch -i ../libiscsi-support-ifm_libgcrypt-instead-of-libgcrypt-spec.patch -p1 < libiscsi.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y libiscsi.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba libiscsi.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build libvhtp successful. rpmfile is in /root/rpmbuild/RPMS/"
