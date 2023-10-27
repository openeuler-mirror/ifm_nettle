# 项目安装
```
$ git clone https://gitee.com/src-openeuler/nghttp2.git
$ cd nghttp2
```
将ifm_nettle/patchs/nghttp2中的文件复制到新拉取的当前nghttp2文件中

```
$ mkdir -p /root/rpmbuild/SOURCES
$ cp * /root/rpmbuild/SOURCES
$ rpmbuild -bb nghttp2.spec
```

编译构建后，在/root/rpmbuild/BUILD中将生成编译成功后的二进制命令。

## 编译构建
在/root/rpmbuild/BUILD/nghttp2中可以通过./configure 参数指定新增基于libverto的nghttp2实现是否参与编译
```
./configure   //  默认不使用libverto 
./configure --with-libverto   // 使用基于libverto实现的工具 
```

## 具体使用方法
https://github.com/Flipped-coder/summer_ospp/blob/master/OSPP项目说明文档.pdf
