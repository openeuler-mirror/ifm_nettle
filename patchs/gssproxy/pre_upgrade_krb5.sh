#!/bin/sh

# 开启gssproxy的make check需要安装master上的krb5
rm krb5 -rf
git clone --depth 1 https://gitee.com/src-openeuler/krb5.git
if [ $? -ne 0 ];then
    echo "Failed: clone and checkout failed, exit"
    exit 1
fi
cd krb5

# 安装依赖
yum builddep -y krb5.spec

# 编译rpm包
rm /root/rpmbuild/SOURCES/* -rf
cp * /root/rpmbuild/SOURCES/ -rf
rpmbuild -ba krb5.spec
if [ $? -ne 0 ];then
    echo "Failed: rpmbuild failed, exit"
    exit 1
fi

# 升级高版本krb5
rpm -Uvh /root/rpmbuild/RPMS/x86_64/krb5-1.21.1-3.x86_64.rpm
rpm --nodeps -Uvh /root/rpmbuild/RPMS/x86_64/krb5-client-1.21.1-3.x86_64.rpm
rpm --nodeps -Uvh /root/rpmbuild/RPMS/x86_64/krb5-server-1.21.1-3.x86_64.rpm
rpm --nodeps -Uvh /root/rpmbuild/RPMS/x86_64/krb5-devel-1.21.1-3.x86_64.rpm
rpm -Uvh /root/rpmbuild/RPMS/x86_64/krb5-libs-1.21.1-3.x86_64.rpm --force
if [ $? -ne 0 ];then
    echo "Failed: krb5 upgrade failed, exit"
    exit 1
fi
