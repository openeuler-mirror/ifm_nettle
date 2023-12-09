#!/bin/sh

# 下载源码
rm pam -rf
git clone -b openEuler-22.03-LTS-SP1 https://gitee.com/src-openeuler/pam.git

# 切换到对应commit
cd pam
git checkout d7ded4041ed2e36ae0c09ae68d5b1f3049441f18
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi

# 拷贝补丁并打上spec补丁
cp ../support-ifm_crypt-instead-of-crypt.patch ./
patch -i ../support-ifm-gcrypt-pam-spec.patch -p1 < pam.spec
if [ $? -ne 0 ];then
    echo "Failed: patch failed, exit"
    exit 1
fi

# 安装依赖
yum builddep -y pam.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba pam.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

echo "SUCCESS: Build systemd successful. rpmfile is in /root/rpmbuild/RPMS/"