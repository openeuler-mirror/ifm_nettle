#!/bin/sh

# 下载源码
rm dnsmasq -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/dnsmasq.git

# 切换到对应commit
cd dnsmasq
git checkout 2eb9dd7d708bb875f75b5f7acbc6234bc9c34647
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-ifm_nettle-instead-of-nettle.patch ./
patch -i ../support-ifm_nettle-instead-of-nettle-spec.patch -p1 < dnsmasq.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y dnsmasq.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba dnsmasq.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build dnsmasq successful. rpmfile is in /root/rpmbuild/RPMS/"
