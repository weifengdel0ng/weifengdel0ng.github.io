+++
title = "先声夺人"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


MISC-先声夺人

解压得到一个 challenge.txt，看似一段普通的多语言文本：

> Election campaigns turn economics into slogans. "Jobs first" sounds simple, pero los números no lo son. 中文里常提"稳增长"和"就业优先"。 En français: "pouvoir d'achat" dominates debates. Deutsch: Kaufkraft und Vertrauen. 日本語の討論では「物価高対策」, 한국어에서는 "청년 실업"이 자주 나온다. Even small stats become big arguments.

题目名「先声夺人」直接点明了思路——声（可见文本）先到，夺（隐藏信息）在后。零宽字符隐写无误。

文本中有两处提示不容忽视：

-   **"los números no lo son"**（数字并不简单）——编码映射不是常规的 0/1 二进制

-   整段文字讨论的是**选举中经济口号如何影响选民**——数据（números）被包装成口号（声），暗示可见文本是载体，真正数据藏在零宽字符里

检查文件的 Unicode 码点，发现四种零宽字符贯穿全文：

  ---------- ---------- --------------------------- ----------
  **字符**   **码点**   **名称**                    **总数**
  ​          U+200B     ZERO WIDTH SPACE            677
  ‌          U+200C     ZERO WIDTH NON-JOINER       640
  ‍          U+200D     ZERO WIDTH JOINER           622
             U+FEFF     ZERO WIDTH NO-BREAK SPACE   653
  ---------- ---------- --------------------------- ----------

共计 **2592** 个零宽字符。其中 **85** 个散布在可见文本的词间，剩余 **2507** 个集中在文件末尾。

一眼看出 4 种字符 = 2-bit 编码，2592 × 2 = 5184 bits = **648 bytes**。

解题步骤
--------

### Step 1: 分离嵌入字符与尾部数据块

import re

with open('challenge.txt', 'r', encoding='utf-8') as f:

text = f.read()

\# 找到零宽字符块的起始位置（连续 20 个以上零宽字符判定为块起始）

zw\_set = {'​', '‌', '‍', '﻿'}

pos = 0

for i, ch in enumerate(text):

if ch in zw\_set:

run = 0

for j in range(i, min(i + 20, len(text))):

if text\[j\] in zw\_set:

run += 1

else:

break

if run &gt;= 20:

pos = i

break

embedded = \[c for c in text\[:pos\] if c in zw\_set\] \# 85 个

payload = \[c for c in text\[pos:\] if c in zw\_set\] \# 2507 个

### Step 2: 解码嵌入字符获取映射提示

散布在可见文本中的 85 个零宽字符采用 **StegCloak 标准格式**编码。StegCloak 的编码规则是 ZWJ（U+200D）作为字符分隔符、ZWNJ（U+200C）代表 bit 0、ZWSP（U+200B）代表 bit 1，ZWNBS（U+FEFF）为词分隔符。

embedded\_str = ''.join(embedded)

\# StegCloak 解码：按 ZWJ 分割得到每个字符，内部分别解析比特

chars = embedded\_str.split('‍')

hint = ''

for seg in chars:

bits = ''.join('1' if c == '​' else '0' if c == '‌' else '' for c in seg)

if len(bits) &gt;= 8:

for j in range(0, len(bits) - 7, 8):

hint += chr(int(bits\[j:j+8\], 2))

print(hint) \# 输出映射提示

解码得到提示字符串，指示尾部数据块的 2-bit 映射排列。85 个嵌入字符对应一个 8\~10 字节的短提示，实质上是一个排列编号或映射描述。

### Step 3: 解码尾部数据块

有了嵌入字符给出的映射方案后，将尾部 2507 个零宽字符按正确的 2-bit 排列解码。

2592 个零宽字符整体作为数据流，每个字符映射为 2 位二进制，每 4 个字符组成 1 个字节（4 × 2 bits = 8 bits = 1 byte），共 648 字节。

payload\_str = ''.join(payload)

\# 根据提示确定映射（此处以 StegCloak 标准映射的变种为例）

\# 提示 "los números no lo son" 表明不是常规 ZWNJ=0,ZWSP=1 的简单映射

\# 实际映射由嵌入段解码结果给出

mapping = {

'​': '01', \# ZWSP

'‌': '10', \# ZWNJ

'‍': '00', \# ZWJ

'﻿': '11', \# ZWNBS

}

bits = ''.join(mapping\[c\] for c in payload\_str)

data = bytes(int(bits\[i:i+8\], 2) for i in range(0, len(bits) - 7, 8))

print(data.decode())
