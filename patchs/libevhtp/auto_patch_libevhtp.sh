#!/bin/sh

# 下载源码
rm libevhtp -rf
git clone https://gitee.com/src-openeuler/libevhtp.git

# 切换到对应commit
cd libevhtp
git checkout 3650a108166e68545165a8180e5779d8df4b36ec
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../ifm-use-libhv-instead-of-libev.patch ./
patch -i ../ifm-libvhtp-spec.patch -p1 < libevhtp.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y libevhtp.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba libevhtp.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build libvhtp successful. rpmfile is in /root/rpmbuild/RPMS/"
