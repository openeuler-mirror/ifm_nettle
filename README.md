#### 介绍
该软件为nettle的接口适配层，支持将部分加解密算法调用鲲鹏硬件提供的加速能力，从而在鲲鹏场景下提供更高的加解密效率。

鲲鹏硬件加速库介绍请点击[链接](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/encryp-decryp/api-kae/kunpengaccel_17_0004.html)

nettle官方网站：http://www.lysator.liu.se/~nisse/nettle/

#### 软件架构
接口上保持同nettle兼容，支持通过配置将部分加解密算法的实现调用鲲鹏加速库提供的接口，硬件未实现的接口，继续调用原有软件的接口进行实现。
整体逻辑架构如下:

                    +----------------+
                    |                |
                    |   inf_nettle   |
                    |                |
                    +----------------+
                           /\
                          /  \
                         /    \
        +----------------+    +----------------+
        |                |    |                |
        |     nettle     |    |    KAE WD接口  |
        |                |    |                |
        +----------------+    +----------------+


#### 安装教程

1.  执行如下命令安装gmock-devel cmake make
```
yum install -y gmock-devel cmake make gcc-c++ nettle-devel libgcrypt-devel
```
2.  使用如下命令clone代码
```
git clone https://gitee.com/openeuler/ifm_nettle.git
```
3.  进入ifm_nettle目录，执行如下命令进行编译
```
sudo mkdir build
cd build
cmake ..
make
```
4. 执行如下命令运行测试用例：
```
ctest
```
5. 执行如下命令安装：
```
make install
```
6. 执行如下命令可以进行压力测试
```
cd bench
./nettle-bench


        Algorithm         mode     Mbyte(512)/s      Mbyte(1K)/s     Mbyte(10K)/s    Mbyte(512K)/s      Mbyte(1M)/s     Mbyte(10M)/s     Mbyte(20M)/s
        ifm_sha224       update         2105.03          2070.77          2121.39          2067.91          2067.10          2084.74          2064.83
        ifm_sha256       update         2038.78          2093.81          2093.56          2092.40          2109.48          2098.20          2080.10
        ifm_sha384       update          591.92           619.40           561.98           652.62           587.42           633.66           618.05
        ifm_sha512       update          659.03           585.36           584.84           612.06           704.24           706.67           629.51
    ifm_sha512_224       update          644.40           640.75           582.09           630.41           608.11           676.31           631.03
    ifm_sha512_256       update          704.07           694.24           699.61           671.89           699.06           584.31           696.86
```
#### 使用说明

1.  xxxx
2.  xxxx
3.  xxxx

#### 仓库Committer
 @huangduirong huangduirong@huawei.com

