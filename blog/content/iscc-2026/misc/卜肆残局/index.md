+++
title = "卜肆残局"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


### MISC-卜肆残局 

**整体思路** 从“四样旧物”中提取四段碎片 -&gt; 拼接成 mid -&gt; 对 mid 取 MD5 得到 窥得天机.zip 密码 -&gt; 读取 ZIP 注释并结合 64 个 txt 文件取出 终局.7z 密码 -&gt; 解开 终局.7z 得到密文 -&gt; 使用 mid 和 7z密码 分别截取 Key、IV 进行 AES-CBC 解密得到 Flag。

### 第一阶段：从“四样旧物”提取四段碎片

#### 1. 天象：分析 天象-铜钱卦.svg

**线索分析**：

-   SVG 的 metadata 提示“外八内八”、“天盘依文王位，记文仍从伏羲次”。

-   “外内同宫”表示同一个卦位取外圈和内圈。

-   伏羲八卦顺序为：乾、兑、离、震、巽、坎、艮、坤。

-   记法：实线 = 1，断线 = 0。

<!-- -->

-   **提取过程**：

    -   每个卦位按“外圈三爻 + 内圈三爻”得到 6bit，对应一个 Base64 字符。

    -   乾(011100=28=c)、兑(010101=21=V)、离(011100=28=c)、震(110010=50=y)

    -   巽(010011=19=T)、坎(110011=51=z)、艮(000001=1=B)、坤(111010=58=6)

-   **结果**：

    -   Base64 字符串：cVcyTzB6

    -   解码得到碎片：qW2O0z

#### 2. 人言：分析 人言-签筒残册.txt

-   **线索分析**：

    -   文件中有八门（休、生、伤、杜、景、死、惊、开），每门有 8 句签文。

    -   每门的 Base64 批注解码后为“去几几”（例如“去三六”即删除第 3、6 句）。

    -   剩余 6 句中，普通句号 。 = 0，小点 ﹒ = 1。

-   **提取过程**：

    -   休门(去三六)：001101

    -   生门(去二七)：010110

    -   伤门(去一八)：001001

    -   杜门(去四五)：101110

    -   景门(去二五)：010010

    -   死门(去三八)：010110

    -   惊门(去一六)：110101

    -   开门(去四七)：000111

-   **结果**：

    -   拼接二进制转 Base64：NWJuSW1H

    -   解码得到碎片：5bnImG

#### 3. 地盘：分析 地理-洛书盘.bmp

-   **线索分析**：

    -   BMP 文件尾部隐藏了 ZIP 数据（搜索 PK\\x03\\x04 提取）。

    -   层层解压（ZIP -&gt; ZIP -&gt; TAR.GZ）后得到 后天九宫.txt。

    -   提示按后天九宫顺序（坎一坤二震三巽四中五乾六兑七艮八离九）取“字契”，并去掉中宫（五）。

-   **提取过程**：

    -   坎一(灯=N)、坤二(砚=H)、震三(瓦=l)、巽四(藤=G)

    -   乾六(鹤=d)、兑七(鼓=V)、艮八(砂=V)、离九(铃=j)

-   **结果**：

    -   Base64 字符串：NHlGdVVj

    -   解码得到碎片：4yFuUc

#### 4. 时令：分析 时令-漏刻历盘.csv

-   **线索分析**：

    -   CSV 为 UTF-16 编码。提示关注“四立二分二至”（立春、春分、立夏、夏至、立秋、秋分、立冬、冬至）。

    -   每个节气的“六断”列中：宜 = 1，忌 = 0。

-   **提取过程**：

    -   立春(001101)、春分(000101)、立夏(100100)、夏至(110000)

    -   立秋(011011)、秋分(100101)、立冬(011000)、冬至(111001)

-   **结果**：

    -   拼接二进制转 Base64：NFkwblY5

    -   解码得到碎片：4Y0nV9

### 第二阶段：解开 窥得天机.zip

将四段碎片按“天象、人言、地盘、时令”顺序拼接，并计算 MD5。

-   **拼接字符串 (mid)**：qW2O0z5bnImG4yFuUc4Y0nV9

-   **MD5 计算**：

> import hashlib
>
> mid = b"qW2O0z5bnImG4yFuUc4Y0nV9"
>
> print(hashlib.md5(mid).hexdigest())
>
> \# 输出: 228a53da12c42a65235ca2ebefa826c1

-   -   **操作**：使用密码 228a53da12c42a65235ca2ebefa826c1 解压 窥得天机.zip，得到 64 个 txt 文件。

### 第三阶段：提取 终局.7z 密码

结合 ZIP 注释和 64 个 txt 文件提取密码。

-   **线索**：窥得天机.zip 的注释是一串 64 位的 Base64 字符串：q7LxP0aR9Yv+u1kC3wFjI2sQmD4oJ6GfXr5hN8KpTtUVeBylHcSgZdWiEOAbMn/z

-   **提取逻辑**：

    1.  注释中的每个字符在标准 Base64 表（A-Z a-z 0-9 + /）中的索引（0-63）。

    2.  用该索引值去对应编号的 txt 文件中提取第 N 个字符。

    3.  拼接 64 个字符即为 7z 密码。

-   **提取脚本**：

> import zipfile, re
>
> base64\_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
>
> zip\_pwd = b"228a53da12c42a65235ca2ebefa826c1"
>
> with zipfile.ZipFile("窥得天机.zip", "r") as z:
>
> comment = z.comment.decode()
>
> txt\_files = sorted(\[i for i in z.infolist() if i.filename.endswith(".txt")\],
>
> key=lambda x: int(re.search(r"(\\d+)", x.filename).group(1)))
>
> seven\_pwd = ""
>
> for info, ch in zip(txt\_files, comment):
>
> idx = base64\_table.index(ch)
>
> data = z.read(info, pwd=zip\_pwd).decode("utf-8")
>
> seven\_pwd += data\[idx\]
>
> print(seven\_pwd)

-   -   **得到 7z 密码**：UQC8TBH7FkJn7bmz7ikjttXfwjvsp99CHBWmH7+M9HxppE7W7a68mo/Ua4cfQUq2

### 第四阶段：AES 解密得 Flag

解压 终局.7z 得到 终局.txt，内容为 Base64 密文。

-   **密文**：7jgRTVRxS/HSsI673SWW2yglLJbYZq295x7Eu6qCEvymWnnhkwyDg/8CduA2gQpF

-   **解密参数**：

    -   **Key**：mid 的前 16 字节 -&gt; qW2O0z5bnImG4yFu

    -   **IV**：7z密码 的前 16 字节 -&gt; UQC8TBH7FkJn7bmz

    -   **模式**：AES-CBC

-   **解密脚本**：

> from base64 import b64decode
>
> from Crypto.Cipher import AES
>
> from Crypto.Util.Padding import unpad
>
> mid = b"qW2O0z5bnImG4yFuUc4Y0nV9"
>
> seven\_pwd = b"UQC8TBH7FkJn7bmz7ikjttXfwjvsp99CHBWmH7+M9HxppE7W7a68mo/Ua4cfQUq2"
>
> ciphertext = b64decode("7jgRTVRxS/HSsI673SWW2yglLJbYZq295x7Eu6qCEvymWnnhkwyDg/8CduA2gQpF")
>
> cipher = AES.new(mid\[:16\], AES.MODE\_CBC, seven\_pwd\[:16\])
>
> flag = unpad(cipher.decrypt(ciphertext), 16)
>
> print(flag.decode())

-   

**最终 Flag**： ISCC{cd1e6a3c-8348-4d9e-a26c-59c269004f84}
