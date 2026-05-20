+++
title = "折叠回声"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


Mobile - 折叠回声

#### 解题思路

这道题叫“折叠回声”，描述里那句“第一声像答案，第二声像线索，第三声才说真话”其实已经把出题人的套路交代得明明白白了——APK里绝对藏着好几层校验或隐藏信息。

所以咱们分析的时候千万别被表面的字符串骗了。第一眼看到的flag大概率就是个“烟雾弹”，真正的flag还得老老实实从资源文件和程序逻辑里去扒。

整个解题流程大概是这样的： APK静态分析 -&gt; 提取DEX字符串 -&gt; 发现第一层假flag -&gt; 检查assets资源文件 -&gt; 发现sleep\_loop.webp中的ECH0隐藏块 -&gt; 解密得到EFVM结构 -&gt; 分析VM输出和expected数据 -&gt; 异或还原真实flag。

#### 一、基础静态分析

先把APK解包看看（用apktool d EchoFold.apk -o EchoFold），或者直接用jadx-gui打开APK看Java伪代码。

在classes.dex里能翻到一些很显眼的字符串： ISCC{、ISCC{...}、ISCC{this\_is\_only\_the\_first\_echo}、fold-echo、vm-seed、sleep\_loop.webp、ECH0、EFVM。

其中最扎眼的就是ISCC{this\_is\_only\_the\_first\_echo}。一开始很容易上头以为这就是flag，但结合题目里那句“第一声很像答案”，基本可以断定这只是第一层用来迷惑你的。

#### 二、第一层假flag分析

反编译代码里能看到类似这样的逻辑： return "ISCC{this\_is\_only\_the\_first\_echo}".equals(input);

当你输入这个字符串时，程序并不会给你最终的正确结果，而是会弹个提示，大概意思是“first echo accepted, but not the real one.”（第一声回声被接受了，但不是真正的那个）。

这就实锤了：ISCC{this\_is\_only\_the\_first\_echo} 只是个用来误导选手的假flag，不是最终答案。

#### 三、分析资源文件sleep\_loop.webp

继续翻APK的资源文件，发现了 assets/sleep\_loop.webp。

虽然它表面上是个WebP图片，但程序里出现了 ECH0 这个字符串，说明程序很可能会从这张图片里读取自定义的数据块。

进一步检查 sleep\_loop.webp，果然发现里面藏了个自定义块：ECH0。程序会读取这个块，再结合APK自身的一些信息进行解密。

参与计算解密key的关键材料包括：fold-echo、resourceKey、dexDigest、certDigest、TRACE。

咱们已经还原出的关键值如下：

-   resourceKey = 010e1f203d4a43547966979885b2abdcf1fecfd02d3a3304

-   dexDigest = c82404bedd319ef962e9c114dcec9566265c140d621319f795c14a0a12d2df77

-   certDigest = 1b62bcb48da1838d72a1ba812f0faa770f57998c5ae595a27f5741b12583e984

-   TRACE = 11237a425166

程序就是根据这些值生成key，去解密那个 ECH0 块。

#### 四、解出EFVM结构

解密之后，得到了一个以 EFVM 开头的数据结构。它的结构大概是这样的：

-   magic = EFVM

-   code\_len = 192

-   out\_len = 35

也就是说，隐藏块里并没有直接保存flag，而是藏了一段VM字节码和一段校验数据。

这里 out\_len=35 非常关键，因为最终flag的主体 f0lded\_echo\_is\_a\_state\_not\_a\_string 长度正好也是35字节。

#### 五、分析VM校验逻辑

程序里藏了一个自定义的VM逻辑，它会根据前面拿到的材料初始化状态，然后执行那192字节的VM代码，最终输出35字节的状态数据。

同时，EFVM 结构里还保存了一个35字节的 expected。还原后得到： expected = acdb243fefe9e4901891c898d05ae9912868ed8a938de6c737c5bba38dc6da3cb08c8c

而VM执行后的输出是： vm\_output = caeb485b8a8dbbf57bf9a7c7b929b6f0771b99ebe7e8b9a958b1e4c2d2b5ae4ed9e2eb

题目真正的核心考点就在这儿： **真实内容 = expected \^ vm\_output** 也就是把这两段35字节的数据逐字节进行异或运算。

#### 六、还原flag

直接用下面这个脚本就能把flag还原出来：

expected = bytes.fromhex(

"acdb243fefe9e4901891c898d05ae9912868ed8a938de6c737c5bba38dc6da3cb08c8c"

)

vm\_output = bytes.fromhex(

"caeb485b8a8dbbf57bf9a7c7b929b6f0771b99ebe7e8b9a958b1e4c2d2b5ae4ed9e2eb"

)

flag\_body = bytes(a \^ b for a, b in zip(expected, vm\_output)).decode()

print("ISCC{" + flag\_body + "}")

运行结果： ISCC{f0lded\_echo\_is\_a\_state\_not\_a\_string}

七、最终flag
============

ISCC{f0lded\_echo\_is\_a\_state\_not\_a\_string}
