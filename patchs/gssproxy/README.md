# krb5升级
由于gssproxy的自动化测试用例依赖新的krb5，因此需要，执行如下命令，自动从src-openEuler仓库下载对应的krb5，自动打补丁、编译并升级环境中的krb5：
```
sh pre_upgrade_krb5.sh
```
该操作在环境中执行一次即可，无需重复执行。

# 项目源码适配以及编译构建
在当前目录下，执行如下命令，自动从src-openEuler仓库下载对应的gssproxy，自动打补丁并进行编译：
```
sh auto_patch_gssproxy.sh
```
编译构建后，在/root/rpmbuild/BUILD中将生成编译成功后的二进制命令，/root/rpmbuild/RPMS/生成新的rpm包。
