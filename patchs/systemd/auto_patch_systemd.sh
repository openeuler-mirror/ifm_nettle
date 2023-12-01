#!/bin/sh

# 下载源码
rm systemd -rf
git clone -b openEuler-20.03-LTS-SP1 https://gitee.com/src-openeuler/systemd.git

# 切换到对应commit
cd systemd
git checkout bb31c60853cb1ecfa7e4958722e8f7aaba2eb59a
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-unizip-instead-of-zlib.patch ./
patch -i ../support-systemd-spec.patch -p1 < systemd.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y systemd.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba systemd.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build systemd successful. rpmfile is in /root/rpmbuild/RPMS/"