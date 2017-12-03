drizzleDumper
===
  
          
简介
===

*drizzleDumper*是一款基于内存搜索的Android脱壳工具。
*drizzleDumper* is a memory-search-based Android unpack tool.
  
  
  
使用方法
===

    ./drizzleDumper package_name wait_times(s)

更详细的使用方法可参考FreeBuf文章：
	http://www.freebuf.com/sectool/105147.html
    
工具集（分别适用于不同加固）
===
drizzleDumper <https://github.com/DrizzleRisk/drizzleDumper>

TUnpacker <https://github.com/DrizzleRisk/TUnpacker>

BUnpacker <https://github.com/DrizzleRisk/BUnpacker>

License
===
	Licensed under the Apache License, Version 2.0 (the "License")
	Some code borrowed from strazzere(https://github.com/strazzere/android-unpacker/tree/master/native-unpacker)
	

//LiuYiAdd
在.mk目录下执行ndk-build即可编译代码。
tools是另外添加的工具，jadx可用以打开dex文件参看源码。

参考文档：
drizzleDumper的原理分析和使用说明  http://blog.csdn.net/qq1084283172/article/details/53561622
                                    http://blog.csdn.net/p2011211616/article/details/75304095
									
常见app加固厂商脱壳方法研究  http://www.mottoin.com/89035.html
fork: http://blog.csdn.net/a332324956/article/details/9114919