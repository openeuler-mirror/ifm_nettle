#!/bin/sh

# 下载源码
rm gssproxy -rf
git clone --depth 1 https://gitee.com/src-openeuler/gssproxy.git

# 切换到对应commit
cd gssproxy
git checkout 519adcbc69c7196e03fc3fcd6c93eea7979b3990
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
# cp ../ifm-use-ifm_libverto-instead-of-verto.patch ./
# patch -i ../ifm-gssproxy-spec.patch -p1 < gssproxy.spec
# if [ $? -ne 0 ];then
#     echo "Failed: patch failed, exit"
#     exit 1
# fi

# 安装依赖
yum builddep -y gssproxy.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba gssproxy.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build gssproxy successful. rpmfile is in /root/rpmbuild/RPMS/"
