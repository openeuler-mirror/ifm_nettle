#!/bin/sh
# 该脚本会自动从openEuler社区下载对应的软件版本，打上patch，并进行构建新的rpm包。

# 下载源码
rm nghttp2 -rf
git clone --depth 1 https://gitee.com/src-openeuler/nghttp2.git

# 切换到对应commit
cd nghttp2
git checkout 459e575df3a29f626af7f9a1e53f2b4279702d39
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../ifm-use-libverto-instead-of-libev.patch ./
cp ../update-build-file.patch ./
patch -i ../ifm-nghttp2-spec.patch -p1 < nghttp2.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# cp ../*.patch ./
# cp ../nghttp2.spec ./ -f
# if [ $? -ne 0 ];then
#     echo "Failed: patch failed, exit"
#     exit 1
# fi

# 安装依赖
yum builddep -y nghttp2.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba nghttp2.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build nghttp2 successful. rpmfile is in /root/rpmbuild/RPMS/"
