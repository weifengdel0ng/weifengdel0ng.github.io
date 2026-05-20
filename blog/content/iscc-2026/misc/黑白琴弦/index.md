+++
title = "黑白琴弦"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Misc + 黑白琴弦

解题思路（必须包含文字说明+截图）

1\. 基础信息

题目附件解开后得到 21 张条码图和一个加密的 \`score.rar\`。题目名称“黑白琴弦”提示信息藏在图像的黑白数据层中，而不是常规文本提示。

2\. 三路信息提取

先提取每张 PNG 的可见 Code128 文本和 PNG Comment，可以恢复出两批 8 字符字符串，其中部分命中固定格式“字母 + 6 位十六进制 + 同字母”。

继续分析图像本体后，发现顶行像素的 R 通道 LSB 还藏着第三路数据。按“顶行、R 通道、LSB、正向、offset 0”提取后，又恢复出另外 5 行同格式字符串，最终补齐 A 到 U 共 21 行十六进制数据。

最终得到的 21 行数据如下：

A -&gt; 1fd57f

B -&gt; 104641

C -&gt; 17595d

D -&gt; 175b5d

E -&gt; 17535d

F -&gt; 104e41

G -&gt; 1fd57f

H -&gt; 000300

I -&gt; 1e5e9d

J -&gt; 11a71f

K -&gt; 05c8cf

L -&gt; 0aac3a

M -&gt; 0057fe

N -&gt; 0015c3

O -&gt; 1fcef8

P -&gt; 104d8f

Q -&gt; 174f3e

R -&gt; 175556

S -&gt; 1753cc

T -&gt; 105ac1

U -&gt; 1fddc8

3\. 还原二维码矩阵

将 A..U 按字母排序，每行 6 位十六进制转成 24 位二进制。因为二维码只需要 21 列，所以枚举每行裁掉 3 位的 4 种起点，同时尝试反色、旋转和镜像组合，再用 OpenCV 的 \`QRCodeDetector\` 解码。

最终在 \`crop\_start=3\`、反色、原向的组合上识别出二维码内容：

\`TvUiXMI1vohhtVf\`

4\. 解压 \`score.rar\`

使用二维码内容 \`TvUiXMI1vohhtVf\` 成功解压 \`score.rar\`，得到：

\`music score.pdf\`

说明二维码结果就是压缩包密码。

5\. 提取乐谱提示

从 PDF 文本层可以直接抽到提示：

\`KEY+bnVtYmVyYWJvdmVsaW5l3\`

将 \`bnVtYmVyYWJvdmVsaW5l\` 进行 Base64 解码，得到：

\`numberaboveline\`

因此提示含义为：

\`KEY + 第 3 行上方的数字\`

查看乐谱第 3 行后，可以读出上方数字为：

\`4151515\`

所以最终 flag 为：

\`ISCC{TvUiXMI1vohhtVf4151515}\`

6\. 验证

先验证 \`TvUiXMI1vohhtVf\` 能正确解开 \`score.rar\`，再结合 PDF 提示和第 3 行数字 \`4151515\` 拼接出完整 flag。

Exp（如有，请粘贴完整代码，不允许截图！）

\`\`\`python

from PIL import Image

import cv2

import numpy as np

rows = {

'A': '1fd57f',

'B': '104641',

'C': '17595d',

'D': '175b5d',

'E': '17535d',

'F': '104e41',

'G': '1fd57f',

'H': '000300',

'I': '1e5e9d',

'J': '11a71f',

'K': '05c8cf',

'L': '0aac3a',

'M': '0057fe',

'N': '0015c3',

'O': '1fcef8',

'P': '104d8f',

'Q': '174f3e',

'R': '175556',

'S': '1753cc',

'T': '105ac1',

'U': '1fddc8',

}

bitrows = \[bin(int(rows\[k\], 16))\[2:\].zfill(24) for k in sorted(rows)\]

qrd = cv2.QRCodeDetector()

for crop\_start in range(4):

mat = \[\[1 if b == '1' else 0 for b in row\[crop\_start:crop\_start+21\]\] for row in bitrows\]

arr = np.array(mat, dtype=np.uint8) \* 255

img = 255 - arr

data, \_, \_ = qrd.detectAndDecode(img)

if data:

print(data) \# TvUiXMI1vohhtVf

\`\`\`

Flag：\`ISCC{TvUiXMI1vohhtVf4151515}\`
