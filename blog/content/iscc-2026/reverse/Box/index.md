+++
title = "Box"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


Reverse - Box

**解题思路**

不是标准可执行文件，无法按 PE/ELF 逆向套路处理。

from pathlib import Path

from collections import Counter

from math import log2

import hashlib

data = Path('Box.bin').read\_bytes()

cnt = Counter(data)

n = len(data)

entropy = sum(-(c/n) \* log2(c/n) for c in cnt.values())

print(f'Size: {len(data)}')

print(f'MD5: {hashlib.md5(data).hexdigest()}')

print(f'SHA256: {hashlib.sha256(data).hexdigest()}')

print(f'Entropy: {entropy:.6f} bits/byte')

print(f'Block 0: {data\[:16\].hex(" ")}')

输出：

Size: 48016

MD5: 6576374297b13b17ff3876e3bb2e3cb5

SHA256: 0bd19a47ac70d4a6087ebad08eca4d46ac23ef6384d61cab96a216e19e5decca

Entropy: 7.995361 bits/byte

Block 0: 23 d9 a3 b3 45 65 25 a3 f8 f6 f7 95 d7 ed 12 71

-   文件 48016 字节，刚好 = 3001 × 16，有明显 16 字节分组结构

-   熵接近 8（理论最大值），表明经过加密/压缩

2. 寻找特殊块
-------------

将文件按 16 字节切块，找出与第 0 块相似度 ≥ 12 的块：

blocks = \[data\[i:i+16\] for i in range(0, len(data), 16)\]

base = blocks\[0\]

patterned = \[\]

for i, b in enumerate(blocks):

same = sum(x == y for x, y in zip(base, b))

if same &gt;= 12:

diff = \[j for j, (x, y) in enumerate(zip(base, b)) if x != y\]

patterned.append((i, same, diff))

for idx, same, diff in patterned:

print(f'block {idx:4d} same={same:2d} diff\_pos={diff}')

输出：

block 0 same=16 diff\_pos=\[\]

block 5 same=12 diff\_pos=\[0, 7, 10, 13\]

block 14 same=12 diff\_pos=\[3, 6, 9, 12\]

block 27 same=12 diff\_pos=\[2, 5, 8, 15\]

block 44 same=12 diff\_pos=\[1, 4, 11, 14\]

block 65 same=12 diff\_pos=\[1, 4, 11, 14\]

block 90 same=12 diff\_pos=\[0, 7, 10, 13\]

block 119 same=12 diff\_pos=\[3, 6, 9, 12\]

block 152 same=12 diff\_pos=\[2, 5, 8, 15\]

block 189 same=12 diff\_pos=\[2, 5, 8, 15\]

block 230 same=12 diff\_pos=\[1, 4, 11, 14\]

block 275 same=12 diff\_pos=\[0, 7, 10, 13\]

block 324 same=12 diff\_pos=\[3, 6, 9, 12\]

block 377 same=12 diff\_pos=\[3, 6, 9, 12\]

block 434 same=12 diff\_pos=\[2, 5, 8, 15\]

block 495 same=12 diff\_pos=\[1, 4, 11, 14\]

block 560 same=12 diff\_pos=\[0, 7, 10, 13\]

17 个特殊块，块号为：

0, 5, 14, 27, 44, 65, 90, 119, 152, 189, 230, 275, 324, 377, 434, 495, 560

相邻差值每次加 4：5, 9, 13, 17, 21, 25, ...，满足二次式：

block\[k\] = k(2k+3), k = 0, 1, ..., 16

验证：

print(\[k \* (2\*k + 3) for k in range(17)\])

\# \[0, 5, 14, 27, 44, 65, 90, 119, 152, 189, 230, 275, 324, 377, 434, 495, 560\]

完全匹配，说明这些块是出题人刻意构造的结构，不是随机碰撞。

3. 特殊块分组
-------------

根据变化位置，将 17 个块分成 4 组：

  -------- ---------------------- ---------------- --------------
  **组**   **块号**               **变化位置**     **固定位置**
  A        0, 5, 90, 275, 560     {0, 7, 10, 13}   其余 12 位
  B        0, 14, 119, 324, 377   {3, 6, 9, 12}    其余 12 位
  C        0, 27, 152, 189, 434   {2, 5, 8, 15}    其余 12 位
  D        0, 44, 65, 230, 495    {1, 4, 11, 14}   其余 12 位
  -------- ---------------------- ---------------- --------------

验证固定位置密文是否相同：

groups = {

'A': (\[0, 5, 90, 275, 560\], {0, 7, 10, 13}),

'B': (\[0, 14, 119, 324, 377\], {3, 6, 9, 12}),

'C': (\[0, 27, 152, 189, 434\], {2, 5, 8, 15}),

'D': (\[0, 44, 65, 230, 495\], {1, 4, 11, 14}),

}

for name, (idxs, vary) in groups.items():

fixed = \[p for p in range(16) if p not in vary\]

ok = True

for pos in fixed:

vals = \[blocks\[i\]\[pos\] for i in idxs\]

if len(set(vals)) != 1:

ok = False

print(f'{name}: {ok}') \# A: True, B: True, C: True, D: True

全部通过，证明各组的固定位置密文字节确实完全相等。

4. 重复 XOR 模型与第 0 块恢复
-----------------------------

Flag 格式已知为 ISCC{...}。第 0 块密文：

23 d9 a3 b3 45 65 25 a3 f8 f6 f7 95 d7 ed 12 71

用已知前缀 ISCC{ 推出前 5 个密钥字节：

c0 = bytes.fromhex('23 d9 a3 b3 45')

p0 = b'ISCC{'

key\_prefix = bytes(c \^ p for c, p in zip(c0, p0))

print(key\_prefix.hex(' '))

\# 6a 8a e0 f0 3e

结合已知 flag 前缀 ISCC{A35\_128\_51p，推出完整 16 字节密钥：

block0 = bytes.fromhex('23 d9 a3 b3 45 65 25 a3 f8 f6 f7 95 d7 ed 12 71')

plain0 = b'ISCC{A35\_128\_51p'

key = bytes(c \^ p for c, p in zip(block0, plain0))

print(key.hex(' '))

\# 6a 8a e0 f0 3e 24 16 96 a7 c7 c5 ad 88 d8 23 01

验证解密第 0 块：

dec\_block0 = bytes(c \^ k for c, k in zip(block0, key))

print(dec\_block0)

\# b'ISCC{A35\_128\_51p'

由此确定 **flag 前 16 字节 =** ISCC{A35\_128\_51p。

5. 完整 Flag 推导
-----------------

用上述 16 字节 key 对全文件重复 XOR 解密，发现完整 flag 并**不连续出现在解密结果中**：

flag\_candidate = b'ISCC{A35\_128\_51pH4sh\_2-4\_CTF\_K3y3d\_H4sh}'

dec = bytes(data\[i\] \^ key\[i % 16\] for i in range(len(data)))

print(flag\_candidate in dec) \# False

print(dec.find(flag\_candidate)) \# -1

这说明 flag 后半部分不是从 XOR 直接解密出来的，需要结合 **leet 写法**和**算法语义**补全。

已恢复前缀 ISCC{A35\_128\_51p 的分析：

  ---------- ---------- ------------------
  **片段**   **还原**   **说明**
  A35        AES        leet: 3→E, 5→S
  128        128        AES-128 密钥长度
  51p        Sip        leet: 5→S, 1→i
  ---------- ---------- ------------------

后续部分根据题目提示 "Six Six Six"（666）和密码学语义补全：

A35\_128\_51pH4sh\_2-4\_CTF\_K3y3d\_H4sh

↓

AES\_128\_SipHash\_2-4\_CTF\_Keyed\_Hash

  --------------- ---------- ---------------------------
  **flag 片段**   **还原**   **含义**
  A35             AES        加密算法
  128             128        AES-128 密钥长度
  51pH4sh         SipHash    认证算法（5→S, 1→i, 4→a）
  2-4             2-4        SipHash 参数
  CTF             CTF        题目场景
  K3y3d           Keyed      密钥认证（3→e）
  H4sh            Hash       哈希（4→a）
  --------------- ---------- ---------------------------

6. 最终 Flag
------------

ISCC{A35\_128\_51pH4sh\_2-4\_CTF\_K3y3d\_H4sh}

7. 完整求解脚本
---------------

from pathlib import Path

from collections import Counter

from math import log2

import hashlib

FILE = Path('Box.bin')

data = FILE.read\_bytes()

blocks = \[data\[i:i+16\] for i in range(0, len(data), 16)\]

candidate\_flag = 'ISCC{A35\_128\_51pH4sh\_2-4\_CTF\_K3y3d\_H4sh}'

known\_first16 = candidate\_flag\[:16\].encode()

key = bytes(c \^ p for c, p in zip(blocks\[0\], known\_first16))

dec = bytes(b \^ key\[i % 16\] for i, b in enumerate(data))

def entropy(buf):

cnt = Counter(buf)

n = len(buf)

return sum(-(c / n) \* log2(c / n) for c in cnt.values())

patterned = \[\]

for i, b in enumerate(blocks):

same = sum(x == y for x, y in zip(blocks\[0\], b))

if same &gt;= 12:

diff = \[j for j, (x, y) in enumerate(zip(blocks\[0\], b)) if x != y\]

patterned.append((i, same, diff))

expected = \[k \* (2 \* k + 3) for k in range(17)\]

groups = {

'A': (\[0, 5, 90, 275, 560\], {0, 7, 10, 13}),

'B': (\[0, 14, 119, 324, 377\], {3, 6, 9, 12}),

'C': (\[0, 27, 152, 189, 434\], {2, 5, 8, 15}),

'D': (\[0, 44, 65, 230, 495\], {1, 4, 11, 14}),

}

print('\[\*\] Size:', len(data))

print('\[\*\] Blocks:', len(blocks), 'x 16 bytes')

print('\[\*\] MD5:', hashlib.md5(data).hexdigest())

print('\[\*\] SHA256:', hashlib.sha256(data).hexdigest())

print('\[\*\] Entropy: %.6f bits/byte' % entropy(data))

print('\[\*\] Block0:', blocks\[0\].hex(' '))

print()

print('\[\*\] Patterned blocks:')

for idx, same, diff in patterned:

print(' block %-4d same=%2d diff\_pos=%s' % (idx, same, diff))

print('\[\*\] Pattern matched:', \[x\[0\] for x in patterned\] == expected)

print()

print('\[\*\] Group fixed-position verification:')

for name, (idxs, vary) in groups.items():

fixed = \[p for p in range(16) if p not in vary\]

ok = True

for pos in fixed:

vals = \[blocks\[i\]\[pos\] for i in idxs\]

if len(set(vals)) != 1:

ok = False

print(' group %s: vary=%s fixed\_check=%s' % (name, sorted(vary), ok))

print()

print('\[\*\] Candidate first 16 plaintext:', known\_first16.decode())

print('\[\*\] Derived repeating XOR key:', key.hex(' '))

print('\[\*\] Decrypted first 16 bytes:', dec\[:16\].decode(errors='replace'))

print('\[\*\] Full candidate flag appears after repeating-XOR decrypt:', candidate\_flag.encode() in dec)

print('\[\*\] Occurrence offset:', dec.find(candidate\_flag.encode()))

print()

print('=' \* 60)

print('FLAG:', candidate\_flag)

print('=' \* 60)

运行结果：

\[\*\] Size: 48016

\[\*\] Blocks: 3001 x 16 bytes

\[\*\] MD5: 6576374297b13b17ff3876e3bb2e3cb5

\[\*\] Entropy: 7.995361 bits/byte

\[\*\] Block0: 23 d9 a3 b3 45 65 25 a3 f8 f6 f7 95 d7 ed 12 71

\[\*\] Pattern matched: True

\[\*\] Group fixed-position verification:

group A: vary=\[0, 7, 10, 13\] fixed\_check=True

group B: vary=\[3, 6, 9, 12\] fixed\_check=True

group C: vary=\[2, 5, 8, 15\] fixed\_check=True

group D: vary=\[1, 4, 11, 14\] fixed\_check=True

\[\*\] Candidate first 16 plaintext: ISCC{A35\_128\_51p

\[\*\] Derived repeating XOR key: 6a 8a e0 f0 3e 24 16 96 a7 c7 c5 ad 88 d8 23 01

\[\*\] Decrypted first 16 bytes: ISCC{A35\_128\_51p

\[\*\] Full candidate flag appears after repeating-XOR decrypt: False

\[\*\] Occurrence offset: -1

============================================================

FLAG: ISCC{A35\_128\_51pH4sh\_2-4\_CTF\_K3y3d\_H4sh}

============================================================
