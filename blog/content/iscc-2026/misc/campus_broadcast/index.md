+++
title = "campus_broadcast"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
# campus_broadcast

## 题目信息

题目提示：

> 别只看图，广播更重要；找到顺序，口令自然会出现。

附件：

- `shnu.jpg`
- `campus_broadcast.wav`

## 解题过程

先检查图片文件，发现图片末尾存在隐藏压缩包特征：

```bash
strings shnu.jpg | grep -i rar
```

可以看到：

```text
TheFollowingIsARarFile
Rar!
```

说明 `shnu.jpg` 后面附加了一个 RAR 文件。

提取 RAR：

```python
from pathlib import Path

data = Path("shnu.jpg").read_bytes()
pos = data.find(b"Rar!")
Path("hidden.rar").write_bytes(data[pos:])
```

尝试打开发现 RAR 被加密，需要密码。

根据题目提示“广播更重要；找到顺序”，分析音频 `campus_broadcast.wav`。对音频做频谱图，可以看到隐藏提示指向海报正面的校训顺序：

```text
厚德博学 求是笃行
```

转换为拼音首字母：

```text
hou de bo xue qiu shi du xing
h   d  b  x   q   s   d  x
```

因此 RAR 密码为：

```text
hdbxqsdx
```

使用该密码解压：

```bash
7z x hidden.rar -phdbxqsdx
```

解压后得到 8 个片段文件：

```text
hou
de
bo
xue
qiu
shi
du
xing
```

内容分别为：

```text
hou  -> wE3r
de   -> T5yU
bo   -> 7iO9
xue  -> pL0k
qiu  -> J2hG
shi  -> 4fD
du   -> 6sA
xing -> 8qQ
```

按照校训顺序：

```text
hou de bo xue qiu shi du xing
```

拼接得到：

```text
wE3rT5yU7iO9pL0kJ2hG4fD6sA8qQ
```

## Flag

```text
ISCC{wE3rT5yU7iO9pL0kJ2hG4fD6sA8qQ}
```
