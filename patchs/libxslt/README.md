# 项目源码适配以及编译构建
在当前目录下，执行如下命令，自动从src-openEuler仓库下载对应的libxslt，自动打补丁并进行编译：
```
sh auto_patch_libxslt.sh
```
编译构建后，在/root/rpmbuild/BUILD中将生成编译成功后的二进制命令，/root/rpmbuild/RPMS/生成新的rpm包。
