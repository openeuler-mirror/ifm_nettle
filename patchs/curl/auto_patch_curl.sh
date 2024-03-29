#!/bin/sh

# 下载源码
rm curl -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/curl.git

# 切换到对应commit
cd curl
git checkout 74101c17aef7778f47e54cbda0d533c4a1134796
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-unizip-instead-of-zlib.patch ./
patch -i ../curl-support-unizip-instead-of-zlib-spec.patch -p1 < curl.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y curl.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba curl.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build curl successful. rpmfile is in /root/rpmbuild/RPMS/"
