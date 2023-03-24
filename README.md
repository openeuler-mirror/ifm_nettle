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

1.  xxxx
2.  xxxx
3.  xxxx

#### 使用说明

1.  xxxx
2.  xxxx
3.  xxxx

#### 仓库Committer
 @huangduirong huangduirong@huawei.com

