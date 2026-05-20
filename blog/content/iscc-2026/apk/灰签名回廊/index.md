+++
title = "灰签名回廊"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

# ISCC2026 WriteUp


**题目类型**: Mobile + Native SO 混合逆向

**题目名称**: 灰签名回廊（Mobile2）

## 解题思路

本题是一道 Android APK 与 Native SO 联合校验的逆向题。flag 被拆分成多个片段分散在 DEX 字节码、native 库和 APK 签名证书中。解题关键在于完整重建从 Java 层到 native 层的五阶段校验链，最后通过 SHA-256 哈希闭壳搜索收尾。

\### 1. APK 解包与整体结构识别

使用 \`zipfile\` 解压 APK，提取三个关键组件：

- **classes.dex** — Java 层校验逻辑，包含多个片段来源类

- **libnative-verify.so** — native 校验库（优先取 x86_64 架构）

- **APK Signing Block v2** — 证书签名区块

Java 层关键类梳理：

- \`SecureValidator\` — 主校验入口，存储前缀编码数组和方法码表

- \`SecretContentProvider\` — 提供第二段校验片段

- \`SecretReceiver\` — 广播接收器，提供第三段片段

- \`SecretActivity\` — 提供第四段尾部标记数据

native 层导出函数：

- \`nativeVerifyPart1\` \~ \`nativeVerifyPart4\` — 四阶段分段校验

- \`nativeChainToken\` — 链式 token 派生

**截图说明**（Jadx 反编译视图）：解包后 DEX 中可看到 \`SecureValidator\` 类包含 \`&lt;init&gt;\` 方法中的 \`filled-new-array\` 指令序列，native 校验函数注册在静态代码块中。

---

\### 2. 前缀恢复 — SecureValidator 构造函数

在 \`SecureValidator.&lt;init&gt;\` 方法中，DEX 指令通过 \`filled-new-array\` 构造了一个 5 元素 int 数组。使用 DEX 字节码解析器提取该数组后，尝试与 0\~255 所有可能的字节做异或，寻找以 \`{\` 结尾且全部可打印的字符串，唯一命中的就是 \`ISCC{\`。

```

int_array = [0x3a, 0x3c, 0x3e, 0x3e, 0x7e] // 示例

xor_key = 0x4e

prefix = ''.join(chr(v \^ 0x4e) for v in int_array) → "ISCC{"

```

DEX 字节码分析中 \`fill-array-data-payload\` 指令指向的数据表用 \`filled-new-array\` 收集的寄存器值索引获得。

---

\### 3. 第一段恢复 — Part1 字节变换

\`SecureValidator.a()\` 方法中存在一个 7 字节的 \`fill-array-data\` 负载，该负载会送入 native 的 \`nativeVerifyPart1\`。

在 native SO 中定位 Part1 变换逻辑：搜索特征字节序列 \`fe c1 80 f1\`（对应 \`inc cl; xor cl, imm8\` 指令），提取立即数得到：

- \`p1_add = 1\`（自增量）

- \`p1_xor\`（异或常量）

逆向变换为：\`plaintext[i] = ((ciphertext[i] \^ p1_xor) - p1_add) & 0xff\`

同时，Part1 的实际校验值还与 APK 证书 SHA-256 的前 4 字节循环异或绑定，这一结果会作为链式 token 第一阶段的输入。

**截图说明**（IDA/Ghidra native 反汇编）：\`nativeVerifyPart1\` 函数中可见循环结构，每条元素先异或立即数再减 1，与目标数组逐字节对比。

---

\### 4. 第二段恢复 — ContentProvider + Part2

\`SecretContentProvider.query()\` 方法内通过 \`filled-new-array\` 构造了 4 个 int 值，随后使用 \`xor-int/lit8\` 指令进行异或解码，得到中间片段 \`frag2\`（\`"Rp4N"\`）。

在 native SO 中定位 Part2 检验逻辑。本题样本使用 **scalar5** 模式（非旧的 SIMD shuffle 模式），特征为 5 字节独立标量检查：

```

字节0: frag2[0] \^ p2_x0

字节1: frag2[1] \^ p2_x1

字节2: frag2[2] // 直通

字节3: frag2[3] \^ p2_x3

字节4: frag2[0] \^ p2_x4

```

从 SO 中通过正则匹配提取 \`x0\`、\`x1\`、\`x3\`、\`x4\` 四个异或常量，计算得出 Part2。

**截图说明**：native 反汇编中 Part2 的五条连续 \`xor\` + \`cmp\` 指令序列，每条对应一个字节位置。

---

\### 5. 第三段恢复 — BroadcastReceiver + Part3

\`SecretReceiver.onReceive()\` 采取三层变换：\`result[i] = i \^ arr_value[i] \^ xor_lit8_const\`。提取 int 数组和异或常量后得 \`frag3\`（\`"oyzz"\`）。

在 native Part3 中定位到首个字节变换 \`frag3[0] = ((cmp_byte - frag3[0]) & 0xff) \^ xor_key\`，后续 4 字节分别与一个 32 位比较常量的各字节做类似运算：

```

p3[0] = ((first_cmp - frag3[0]) & 0xff) \^ xor

p3[i+1] = ((cmp[i] - frag3[idx[i]]) & 0xff) \^ xor

```

从 SO 中用 \`0f b6 03 34 .. 41 02 45 00 3c\` 模式定位单字节常量，用 \`66 0f fc c8 66 0f 7e c8 3d\` 定位 32 位比较常量。

---

\### 6. 证书绑定与链式 Token 派生

**APK 证书提取**：从 APK Signing Block v2（魔数 \`APK Sig Block 42\`）中解析 pair ID 为 \`0x7109871a\` 的 signer block，提取第一个证书的 DER 编码，计算 SHA-256，得到 32 字节证书摘要。

**链式 Token 构造**：

```

token = chain_token(stage, seed, input_blob)

内部逻辑:

x = (stage * 0x100000001b3) \^ seed

for each byte b in blob:

x = rol64(((b \^ x) * 0x100000001b3), 13)

x = x \^ (x &gt;&gt; 33)

x = (x * 0xff51afd7ed558ccd) mod 2\^64

x = x \^ (x &gt;&gt; 33)

```

第一阶段输入为 \`native_p1_return\`（Part1 负载异或证书前 4 字节的结果），第二阶段输入 \`frag2\`，第三阶段输入 \`frag3\`。

**截图说明**：从 APK 二进制中定位 \`APK Sig Block 42\` 标记和后续的 signer pair 结构，16 进制视图中可见证书 DER 序列。

---

\### 7. Part4 — RC4 密钥流与位掩码约束

从链式 token 第三阶段输出提取低 4 字节，异或 \`"Secu"\` 常量后作为 RC4 密钥前缀：

```

chain_low = token_bytes[0:4]

key_prefix = chain_low \^ b"Secu"

rc4_key = key_prefix + frag2 + frag3 + [0, 0]

keystream = rc4(rc4_key, 4) → [236, 72, 50, 39]

```

Part4 使用位掩码约束来大幅压缩搜索空间：

```

条件: (((o2 \^ (o1 &lt;&lt; 3) \^ (o0 &lt;&lt; 6)) &lt;&lt; 12) \^ (o3 &lt;&lt; 9)) & 0x03ff0000 == 0x02c40000

其中 o[i] = candidate_byte[i] \^ keystream[i]

```

该条件只检查 32 位结果中的 10 个 bit 位（mask = \`0x03ff0000\`），因此大量候选组合可以通过筛选。但结合已知前缀和最终 SHA-256 闭合验证，唯一正确的候选会被锁定。

---

\### 8. 最终闭壳搜索

已知前缀为 \`ISCC{FkJVk55_PfVw_v5qx\`（22 字节），还需恢复 7 字节内容，末尾字节固定为 \`}\`，总长度 30 字节恰好占一个 SHA-256 块。

搜索策略：

1\. 在大小为 64 的字符集上，对 Part4 的前 4 字节用位掩码条件筛选，获得候选四元组集合

2\. 对每个候选四元组，在后 3 字节空间上三层循环，计算 SHA-256

3\. 与目标哈希 \`c6f81b343cb4dc69b6a62e5af71541119c861658c72a1167ad539cf5422f4d59\` 对比

4\. 命中后输出完整 flag

采用 numba JIT 编译加速 SHA-256 计算，配合并行化在秒级完成搜索。

---

## Exp

完整解题脚本如下（Python 3），核心模块包括 DEX 解析器、APK 证书提取、native 常量匹配、分阶段还原和闭壳搜索。

```python

\#!/usr/bin/env python3

"""

ISCC2026 Mobile2 "灰签名回廊" 解题脚本

流程：解包APK → 解析DEX → 提取native常量 → 恢复Part1-3 → RC4+位掩码筛选 → SHA-256闭壳搜索

"""

import base64

import hashlib

import os

import re

import struct

import subprocess

import sys

import tempfile

import zipfile

from pathlib import Path

MASK64 = (1 &lt;&lt; 64) - 1

def uleb(data, off):

res = 0

shift = 0

while True:

b = data[off]

off += 1

res |= (b & 0x7f) &lt;&lt; shift

if b &lt; 0x80:

return res, off

shift += 7

def signed(v, bits):

if v & (1 &lt;&lt; (bits - 1)):

v -= 1 &lt;&lt; bits

return v

class Dex:

"""精简 DEX 解析器 —— 解析字符串表、类方法表、指令序列及填充数组"""

def __init__(self, data: bytes):

self.data = data

d = data

self.string_ids_size, self.string_ids_off = struct.unpack_from('&lt;II', d, 56)

self.type_ids_size, self.type_ids_off = struct.unpack_from('&lt;II', d, 64)

self.proto_ids_size, self.proto_ids_off = struct.unpack_from('&lt;II', d, 72)

self.field_ids_size, self.field_ids_off = struct.unpack_from('&lt;II', d, 80)

self.method_ids_size, self.method_ids_off = struct.unpack_from('&lt;II', d, 88)

self.class_defs_size, self.class_defs_off = struct.unpack_from('&lt;II', d, 96)

self.strings = []

for i in range(self.string_ids_size):

off = struct.unpack_from('&lt;I', d, self.string_ids_off + i * 4)[0]

_, off2 = uleb(d, off)

end = d.index(b'\\x00', off2)

self.strings.append(d[off2:end].decode('utf-8', 'replace'))

self.types = [self.strings[struct.unpack_from('&lt;I', d, self.type_ids_off + i * 4)[0]]

for i in range(self.type_ids_size)]

self.methods = []

for i in range(self.method_ids_size):

cls, proto, name = struct.unpack_from('&lt;HHI', d, self.method_ids_off + i * 8)

self.methods.append((self.types[cls], self.strings[name]))

self.class_methods = {}

for c in range(self.class_defs_size):

vals = struct.unpack_from('&lt;IIIIIIII', d, self.class_defs_off + 32 * c)

cname = self.types[vals[0]]

class_data_off = vals[6]

if class_data_off:

self.class_methods[cname] = self._parse_class_data(class_data_off)

def _parse_class_data(self, off):

d = self.data

static_fields, off = uleb(d, off)

instance_fields, off = uleb(d, off)

direct_methods, off = uleb(d, off)

virtual_methods, off = uleb(d, off)

for _ in range(static_fields + instance_fields):

_, off = uleb(d, off)

_, off = uleb(d, off)

out = []

midx = 0

for _ in range(direct_methods):

diff, off = uleb(d, off)

_, off = uleb(d, off)

code_off, off = uleb(d, off)

midx += diff

cls, name = self.methods[midx]

out.append((name, code_off, 'direct'))

midx = 0

for _ in range(virtual_methods):

diff, off = uleb(d, off)

_, off = uleb(d, off)

code_off, off = uleb(d, off)

midx += diff

cls, name = self.methods[midx]

out.append((name, code_off, 'virtual'))

return out

def method_code(self, class_contains: str, method_name: str):

for cname, methods in self.class_methods.items():

if class_contains in cname:

for name, code_off, _ in methods:

if name == method_name and code_off:

return code_off

raise ValueError(f'method not found: {class_contains}-&gt;{method_name}')

def insns(self, code_off):

d = self.data

regs, ins, outs, tries, debug, insn_size = struct.unpack_from('&lt;HHHHII', d, code_off)

start = code_off + 16

pc = 0

while pc &lt; insn_size:

off = start + pc * 2

w = struct.unpack_from('&lt;H', d, off)[0]

op = w & 0xff

hi = w &gt;&gt; 8

size = 1

info = {'pc': pc, 'op': op, 'hi': hi, 'off': off}

def u16(n): return struct.unpack_from('&lt;H', d, off + 2 * n)[0]

def s16(n): return signed(u16(n), 16)

def u32(n): return struct.unpack_from('&lt;I', d, off + 2 * n)[0]

def s32(n): return signed(u32(n), 32)

if op == 0x00 and hi == 0x03:

width = struct.unpack_from('&lt;H', d, off + 2)[0]

sz = struct.unpack_from('&lt;I', d, off + 4)[0]

size = 4 + ((width * sz + 1) // 2)

info.update({'payload': True, 'width': width, 'array_size': sz})

elif op in (0x00, 0x0e):

pass

elif op == 0x12:

info.update({'A': hi & 0xf, 'lit': signed(hi &gt;&gt; 4, 4)})

elif op == 0x13:

size = 2

info.update({'A': hi, 'lit': s16(1)})

elif op == 0x14:

size = 3

info.update({'A': hi, 'lit': s32(1)})

elif op == 0x1a:

size = 2

idx = u16(1)

info.update({'A': hi, 'string': self.strings[idx]})

elif op == 0x24:

size = 3

A = hi &gt;&gt; 4

G = hi & 0xf

w2 = u16(2)

regs_list = [w2 & 0xf, (w2 &gt;&gt; 4) & 0xf, (w2 &gt;&gt; 8) & 0xf, (w2 &gt;&gt; 12) & 0xf, G][:A]

info.update({'regs': regs_list})

elif op == 0x26:

size = 3

info.update({'A': hi, 'target_pc': pc + s32(1)})

elif op == 0xdf:

size = 2

w2 = u16(1)

info.update({'A': hi, 'B': w2 & 0xff, 'lit': signed(w2 &gt;&gt; 8, 8)})

elif op in (0x01, 0x04, 0x07, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,

0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f):

pass

elif op in (0x02, 0x05, 0x08, 0x1c, 0x1f, 0x22, 0x23, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,

0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,

0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d) or 0xd0 &lt;= op &lt;= 0xe2:

size = 2

elif op in (0x03, 0x06, 0x09, 0x18, 0x1b, 0x25, 0x2a, 0x2b, 0x2c, 0x6e, 0x6f, 0x70, 0x71,

0x72, 0x74, 0x75, 0x76, 0x77, 0x78):

size = 3 if op != 0x18 else 5

elif op in (0x16, 0x17, 0x15, 0x19, 0x29) or 0x2d &lt;= op &lt;= 0x3d or 0x44 &lt;= op &lt;= 0x51 or 0x90 &lt;= op &lt;= 0xaf:

size = 2

elif 0xb0 &lt;= op &lt;= 0xcf:

pass

else:

size = 1

yield info

pc += size

def fill_payload(self, code_off, target_pc):

d = self.data

start = code_off + 16

off = start + target_pc * 2

ident, width = struct.unpack_from('&lt;HH', d, off)

if ident != 0x0300:

raise ValueError('bad fill-array-data payload')

sz = struct.unpack_from('&lt;I', d, off + 4)[0]

raw = d[off + 8: off + 8 + width * sz]

vals = []

for i in range(sz):

if width == 1:

vals.append(raw[i])

elif width == 2:

vals.append(struct.unpack_from('&lt;H', raw, i * 2)[0])

elif width == 4:

vals.append(struct.unpack_from('&lt;I', raw, i * 4)[0])

elif width == 8:

vals.append(struct.unpack_from('&lt;Q', raw, i * 8)[0])

return width, vals

def const_arrays(self, code_off):

regs = {}

arrays = []

for ins in self.insns(code_off):

op = ins['op']

if op in (0x12, 0x13, 0x14):

regs[ins['A']] = ins['lit']

elif op == 0x24:

vals = []

ok = True

for r in ins['regs']:

if r not in regs:

ok = False

break

vals.append(regs[r])

if ok:

arrays.append((ins['pc'], vals))

return arrays

def fill_arrays(self, code_off):

out = []

for ins in self.insns(code_off):

if ins['op'] == 0x26:

width, vals = self.fill_payload(code_off, ins['target_pc'])

out.append((ins['pc'], width, vals))

return out

def xor_lit8_after(self, code_off, pc_min=-1):

for ins in self.insns(code_off):

if ins['pc'] &gt; pc_min and ins['op'] == 0xdf:

return ins['lit'] & 0xff

raise ValueError('xor-int/lit8 constant not found')

def extract_apk_cert_sha256(apk_bytes: bytes):

"""从 APK v2 签名块中提取签名证书并计算 SHA-256"""

eocd = apk_bytes.rfind(b'PK\\x05\\x06')

if eocd &lt; 0:

raise ValueError('EOCD not found')

cd_off = struct.unpack_from('&lt;I', apk_bytes, eocd + 16)[0]

if apk_bytes[cd_off - 16:cd_off] != b'APK Sig Block 42':

raise ValueError('APK Signing Block not found')

size2 = struct.unpack_from('&lt;Q', apk_bytes, cd_off - 24)[0]

start = cd_off - (size2 + 8)

size1 = struct.unpack_from('&lt;Q', apk_bytes, start)[0]

if size1 != size2:

raise ValueError('APK Signing Block size mismatch')

pos = start + 8

end = cd_off - 24

def read_u32_len(buf, off):

n = struct.unpack_from('&lt;I', buf, off)[0]

return buf[off + 4:off + 4 + n], off + 4 + n

certs = []

while pos &lt; end:

pair_len = struct.unpack_from('&lt;Q', apk_bytes, pos)[0]

pos += 8

pair_id = struct.unpack_from('&lt;I', apk_bytes, pos)[0]

val = apk_bytes[pos + 4:pos + pair_len]

pos += pair_len

if pair_id in (0x7109871a,):

signers, _ = read_u32_len(val, 0)

off = 0

while off &lt; len(signers):

signer, off = read_u32_len(signers, off)

signed_data, o = read_u32_len(signer, 0)

cert_seq, o2 = read_u32_len(signed_data, o)

c_off = 0

while c_off &lt; len(cert_seq):

cert, c_off = read_u32_len(cert_seq, c_off)

certs.append(cert)

if not certs:

raise ValueError('signing certificate not found')

return hashlib.sha256(certs[0]).digest()

def pick_native_so(zf: zipfile.ZipFile):

names = zf.namelist()

preferred = [

'lib/x86_64/libnative-verify.so',

'lib/x86/libnative-verify.so',

'lib/arm64-v8a/libnative-verify.so',

'lib/armeabi-v7a/libnative-verify.so',

]

for n in preferred:

if n in names:

return n, zf.read(n)

for n in names:

if n.endswith('/libnative-verify.so'):

return n, zf.read(n)

raise ValueError('libnative-verify.so not found')

def extract_native_consts(so: bytes):

"""从 native SO 中扫描特征指令提取各阶段变换常量"""

c = {}

# Part1: inc cl; xor cl, imm8 (或 add cl, imm8; xor cl, imm8)

xs = list(re.finditer(rb'\\xfe\\xc1\\x80\\xf1(.)', so, re.S))

if xs:

c['p1_add'] = 1

c['p1_xor'] = xs[-1].group(1)[0]

else:

m = re.search(rb'\\x80\\xc1(.)\\x80\\xf1(.)', so, re.S)

if not m:

raise ValueError('part1 transform constants not found')

c['p1_add'] = m.group(1)[0]

c['p1_xor'] = m.group(2)[0]

# Part2: 优先匹配新 scalar5 模式，回退到旧 SIMD shuffle 模式

m = re.search(rb'\\x41\\x32\\x4d\\x00\\x80\\xf9(.)\\x0f\\x94\\xc0.*?\\x66\\x0f\\x38\\x00\\x0d(.{4}).*?\\x81\\xf9(.{4})', so, re.S)

if m:

c['p2_mode'] = 'shuffle'

c['p2_first_cmp'] = m.group(1)[0]

disp_off = m.start(2)

disp = struct.unpack('&lt;i', m.group(2))[0]

mask_off = disp_off + 4 + disp

mask = so[mask_off:mask_off + 16]

c['p2_mask'] = list(mask[:4])

c['p2_cmp'] = struct.unpack('&lt;I', m.group(3))[0]

else:

m = re.search(

rb'\\x30\\xc2\\x80\\xf2(.)'

rb'\\x41\\x32\\x4c\\x24\\x01\\x80\\xf1(.)'

rb'\\x41\\x0f\\xb6\\x75\\x02\\x41\\x32\\x74\\x24\\x02\\x40\\x08\\xce'

rb'\\x41\\x0f\\xb6\\x4d\\x03\\x41\\x32\\x4c\\x24\\x03\\x80\\xf1(.)'

rb'\\x41\\x32\\x44\\x24\\x04\\x34(.)',

so, re.S,

)

if not m:

raise ValueError('part2 constants not found')

c['p2_mode'] = 'scalar5'

c['p2_x0'] = m.group(1)[0]

c['p2_x1'] = m.group(2)[0]

c['p2_x3'] = m.group(3)[0]

c['p2_x4'] = m.group(4)[0]

# Part3: 首字节异或和比较常量，后续 4 字节 32 位比较

m = re.search(rb'\\x0f\\xb6\\x03\\x34(.)\\x41\\x02\\x45\\x00\\x3c(.)', so, re.S)

if not m:

raise ValueError('part3 first-byte constants not found')

c['p3_xor'] = m.group(1)[0]

c['p3_first_cmp'] = m.group(2)[0]

m = re.search(rb'\\x66\\x0f\\xfc\\xc8\\x66\\x0f\\x7e\\xc8\\x3d(.{4})', so, re.S)

if not m:

raise ValueError('part3 cmp constant not found')

c['p3_cmp'] = struct.unpack('&lt;I', m.group(1))[0]

# Part4: 位掩码与期望值 (AND mask; CMP expected)

ms = list(re.finditer(rb'\\x25(.{4})\\x3d(.{4})\\x0f\\x94\\xc0', so, re.S))

if not ms:

raise ValueError('part4 mask/cmp not found')

m = ms[-1]

c['p4_mask'] = struct.unpack('&lt;I', m.group(1))[0]

c['p4_cmp'] = struct.unpack('&lt;I', m.group(2))[0]

c['chain_seed_xor'] = b'Secu'

return c

def rol64(x, r):

return ((x &lt;&lt; r) | (x &gt;&gt; (64 - r))) & MASK64

def chain_token(stage: int, seed: int, blob: bytes) -&gt; int:

"""链式 token 派生：每阶段用 stage * prime \^ seed 初始化，然后吸收 blob 每个字节"""

prime = 0x100000001b3

x = ((stage * prime) & MASK64) \^ (seed & MASK64)

for b in blob:

x = rol64(((b \^ x) * prime) & MASK64, 13)

x \^= x &gt;&gt; 33

x = (x * 0xff51afd7ed558ccd) & MASK64

x \^= x &gt;&gt; 33

return x & MASK64

def rc4_keystream(key: bytes, n: int):

S = list(range(256))

j = 0

for i in range(256):

j = (j + S[i] + key[i % len(key)]) & 0xff

S[i], S[j] = S[j], S[i]

i = j = 0

out = []

for _ in range(n):

i = (i + 1) & 0xff

j = (j + S[i]) & 0xff

S[i], S[j] = S[j], S[i]

out.append(S[(S[i] + S[j]) & 0xff])

return bytes(out)

def solve_parts(apk_path: str):

apk_bytes = Path(apk_path).read_bytes()

with zipfile.ZipFile(apk_path, 'r') as zf:

dex = Dex(zf.read('classes.dex'))

so_name, so = pick_native_so(zf)

nconst = extract_native_consts(so)

cert_sha = extract_apk_cert_sha256(apk_bytes)

# 目标 SHA-256 在 DEX 字符串表中，固定 64 位 hex 串

hex64 = [s for s in dex.strings if re.fullmatch(r'[0-9a-fA-F]{64}', s)]

if not hex64:

raise ValueError('target SHA-256 string not found')

target_hex = hex64[0].lower()

# ---- 前缀: ISCC{ ----

init_code = dex.method_code('com/example/gnd/security/SecureValidator;', '&lt;init&gt;')

prefix_arr = None

for pc, vals in dex.const_arrays(init_code):

if len(vals) == 5:

prefix_arr = vals

break

if prefix_arr is None:

raise ValueError('flag prefix array not found')

prefix_candidates = []

for x in range(256):

s = ''.join(chr((v \^ x) & 0xff) for v in prefix_arr)

if s.endswith('{') and all(32 &lt;= ord(ch) &lt; 127 for ch in s[:-1]):

prefix_candidates.append((x, s))

if not prefix_candidates:

raise ValueError('flag prefix xor key not found')

prefer = [s for _, s in prefix_candidates if re.match(r'\^[A-Za-z0-9_]+\\{\$', s)]

flag_prefix = ('ISCC{' if any(s == 'ISCC{' for s in prefer) else (prefer[0] if prefer else prefix_candidates[0][1]))

# ---- Part1: SecureValidator.a 字节数组 → native 逆变换 ----

a_code = dex.method_code('com/example/gnd/security/SecureValidator;', 'a')

p1_payloads = [vals for _, w, vals in dex.fill_arrays(a_code) if w == 1 and len(vals) == 7]

if not p1_payloads:

raise ValueError('part1 payload not found')

p1_payload = bytes(p1_payloads[0])

part1 = bytes((((b \^ nconst['p1_xor']) - nconst['p1_add']) & 0xff) for b in p1_payload)

native_p1_return = bytes(p1_payload[i] \^ cert_sha[i % 4] for i in range(len(p1_payload)))

# ---- frag2: ContentProvider ----

provider_code = dex.method_code('com/example/gnd/hidden/SecretContentProvider;', 'query')

prov_arrs = [(pc, vals) for pc, vals in dex.const_arrays(provider_code) if len(vals) == 4]

if not prov_arrs:

raise ValueError('provider fragment array not found')

pc2, arr2 = prov_arrs[0]

imm2 = dex.xor_lit8_after(provider_code, pc2)

frag2 = bytes((v \^ imm2) & 0xff for v in arr2)

# ---- frag3: Receiver ----

recv_code = dex.method_code('com/example/gnd/hidden/SecretReceiver;', 'onReceive')

recv_arrs = [(pc, vals) for pc, vals in dex.const_arrays(recv_code) if len(vals) == 4]

if not recv_arrs:

raise ValueError('receiver fragment array not found')

pc3, arr3 = recv_arrs[-1]

imm3 = dex.xor_lit8_after(recv_code, pc3)

frag3 = bytes(((i \^ v \^ imm3) & 0xff) for i, v in enumerate(arr3))

# ---- frag4: Activity (尾部 2 字节标记) ----

act_code = dex.method_code('com/example/gnd/hidden/SecretActivity;', 'onCreate')

byte_payloads = [bytes(vals) for _, w, vals in dex.fill_arrays(act_code) if w == 1 and len(vals) &gt;= 2]

if not byte_payloads:

raise ValueError('activity fragment payload not found')

payload4 = next((p for p in byte_payloads if b'ISCC' in p), byte_payloads[0])

frag4 = payload4[-2:]

# ---- Part2: native 第二阶段 5 字节标量方程 ----

key2 = frag2

p2 = [0] * 5

if nconst.get('p2_mode') == 'scalar5':

p2[0] = key2[0] \^ nconst['p2_x0']

p2[1] = key2[1] \^ nconst['p2_x1']

p2[2] = key2[2]

p2[3] = key2[3] \^ nconst['p2_x3']

p2[4] = key2[0] \^ nconst['p2_x4']

else:

p2[0] = key2[0] \^ nconst['p2_first_cmp']

cmp2 = nconst['p2_cmp'].to_bytes(4, 'little')

arr = [0] * 4

mask = nconst['p2_mask']

for i, m in enumerate(mask):

if m &lt; 4:

arr[m] = cmp2[i] \^ key2[i]

p2[1:5] = arr

part2 = bytes(p2)

# ---- Part3: native 第三阶段首字节变换 + 4 字节反馈 ----

key3 = frag3

cmp3 = nconst['p3_cmp'].to_bytes(4, 'little')

p3 = [0] * 5

p3[0] = ((nconst['p3_first_cmp'] - key3[0]) & 0xff) \^ nconst['p3_xor']

idxs = [1 if len(key3) != 1 else 0, 2 % len(key3), 3 % len(key3), 4 % len(key3)]

for i in range(4):

p3[i + 1] = ((cmp3[i] - key3[idxs[i]]) & 0xff) \^ nconst['p3_xor']

part3 = bytes(p3)

# ---- 链式 token → RC4 密钥流 ----

seed = 1597463007

ch = chain_token(1, seed, native_p1_return)

ch = chain_token(2, ch, frag2)

ch = chain_token(3, ch, frag3)

chain_low = bytes((ch &gt;&gt; (8 * i)) & 0xff for i in range(4))

key_prefix = bytes(chain_low[i] \^ nconst['chain_seed_xor'][i] for i in range(4))

rc4_key = key_prefix + frag2 + frag3 + bytes([0, 0])

ks = rc4_keystream(rc4_key, 4)

known_prefix = (flag_prefix.encode() + part1 + part2 + part3)

return {

'target_hex': target_hex,

'flag_prefix': flag_prefix,

'part1': part1,

'part2': part2,

'part3': part3,

'frag2': frag2,

'frag3': frag3,

'frag4': frag4,

'known_prefix': known_prefix,

'ks': ks,

'p4_mask': nconst['p4_mask'],

'p4_cmp': nconst['p4_cmp'],

'so_name': so_name,

}

def brute_with_numba(info):

"""numba JIT 加速的 SHA-256 闭壳搜索"""

try:

import itertools

import numpy as np

from numba import njit, prange

except Exception:

return None

full = os.environ.get('CHARSET', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')

upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'

ks = info['ks']

mask = info['p4_mask']

cmpv = info['p4_cmp']

target = bytes.fromhex(info['target_hex'])

prefix = info['known_prefix']

# 位掩码预筛选：生成满足 part4 前 4 字节约束的所有候选

cand4 = []

for bcd in itertools.product(full, repeat=3):

s = '_' + ''.join(bcd)

a, b, c, d = [ord(x) for x in s]

o0, o1, o2, o3 = a \^ ks[0], b \^ ks[1], c \^ ks[2], d \^ ks[3]

if (((((o2 \^ (o1 &lt;&lt; 3) \^ (o0 &lt;&lt; 6)) &lt;&lt; 12) \^ (o3 &lt;&lt; 9)) & mask) == cmpv):

cand4.append([a, b, c, d])

if not cand4:

return None

cand4 = np.array(cand4, dtype=np.uint8)

upper_arr = np.frombuffer(upper.encode(), dtype=np.uint8)

full_arr = np.frombuffer(full.encode(), dtype=np.uint8)

target_words = np.frombuffer(target, dtype='&gt;u4').astype(np.uint32)

prefix_arr = np.frombuffer(prefix, dtype=np.uint8)

ktab = np.array([

0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,

0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,

0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,

0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,

0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,

0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,

0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,

0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

], dtype=np.uint32)

@njit(inline='always')

def rotr(x, n):

return ((x &gt;&gt; n) | (x &lt;&lt; (32 - n))) & np.uint32(0xffffffff)

@njit(inline='always')

def ch(x, y, z):

return (x & y) \^ ((\~x) & z)

@njit(inline='always')

def maj(x, y, z):

return (x & y) \^ (x & z) \^ (y & z)

@njit(inline='always')

def ep0(x):

return rotr(x, 2) \^ rotr(x, 13) \^ rotr(x, 22)

@njit(inline='always')

def ep1(x):

return rotr(x, 6) \^ rotr(x, 11) \^ rotr(x, 25)

@njit(inline='always')

def sig0(x):

return rotr(x, 7) \^ rotr(x, 18) \^ (x &gt;&gt; 3)

@njit(inline='always')

def sig1(x):

return rotr(x, 17) \^ rotr(x, 19) \^ (x &gt;&gt; 10)

@njit(inline='always')

def check_bytes(p4, t0, t1, t2, prefix_arr_, target_words_, ktab_):

block = np.zeros(64, dtype=np.uint8)

plen = prefix_arr_.shape[0]

for i in range(plen):

block[i] = prefix_arr_[i]

block[plen:plen + 4] = p4

block[plen + 4] = t0

block[plen + 5] = t1

block[plen + 6] = t2

block[plen + 7] = ord('}')

total = plen + 8

block[total] = 0x80

bitlen = np.uint64(total * 8)

for i in range(8):

block[63 - i] = np.uint8(bitlen &gt;&gt; (8 * i))

w = np.zeros(64, dtype=np.uint32)

for i in range(16):

j = i * 4

w[i] = (np.uint32(block[j]) &lt;&lt; 24) | (np.uint32(block[j + 1]) &lt;&lt; 16) | (np.uint32(block[j + 2]) &lt;&lt; 8) | np.uint32(block[j + 3])

for i in range(16, 64):

w[i] = (sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16]) & np.uint32(0xffffffff)

a = np.uint32(0x6a09e667); b = np.uint32(0xbb67ae85)

c = np.uint32(0x3c6ef372); d = np.uint32(0xa54ff53a)

e = np.uint32(0x510e527f); f = np.uint32(0x9b05688c)

g = np.uint32(0x1f83d9ab); h = np.uint32(0x5be0cd19)

for i in range(64):

t1v = (h + ep1(e) + ch(e, f, g) + ktab_[i] + w[i]) & np.uint32(0xffffffff)

t2v = (ep0(a) + maj(a, b, c)) & np.uint32(0xffffffff)

h = g; g = f; f = e; e = (d + t1v) & np.uint32(0xffffffff)

d = c; c = b; b = a; a = (t1v + t2v) & np.uint32(0xffffffff)

h0 = (np.uint32(0x6a09e667) + a) & np.uint32(0xffffffff)

h1 = (np.uint32(0xbb67ae85) + b) & np.uint32(0xffffffff)

h2 = (np.uint32(0x3c6ef372) + c) & np.uint32(0xffffffff)

h3 = (np.uint32(0xa54ff53a) + d) & np.uint32(0xffffffff)

h4 = (np.uint32(0x510e527f) + e) & np.uint32(0xffffffff)

h5 = (np.uint32(0x9b05688c) + f) & np.uint32(0xffffffff)

h6 = (np.uint32(0x1f83d9ab) + g) & np.uint32(0xffffffff)

h7 = (np.uint32(0x5be0cd19) + h) & np.uint32(0xffffffff)

return (h0 == target_words_[0] and h1 == target_words_[1] and

h2 == target_words_[2] and h3 == target_words_[3] and

h4 == target_words_[4] and h5 == target_words_[5] and

h6 == target_words_[6] and h7 == target_words_[7])

@njit(parallel=True)

def search(cand4_, tail_arr_, prefix_arr_, target_words_, ktab_):

out = np.zeros(7, dtype=np.uint8)

found = np.zeros(1, dtype=np.uint8)

for i in prange(cand4_.shape[0]):

if found[0]: continue

p4 = cand4_[i]

for a in tail_arr_:

if found[0]: break

for b in tail_arr_:

if found[0]: break

for c in tail_arr_:

if check_bytes(p4, a, b, c, prefix_arr_, target_words_, ktab_):

out[0:4] = p4; out[4] = a; out[5] = b; out[6] = c

found[0] = 1; break

return found[0], out

search(cand4[:1], upper_arr[:1], prefix_arr, target_words, ktab)

found, out = search(cand4, upper_arr, prefix_arr, target_words, ktab)

if not found:

found, out = search(cand4, full_arr, prefix_arr, target_words, ktab)

if not found:

return None

return bytes(prefix_arr.tolist() + out.tolist() + [ord('}')]).decode()

def brute_python_reduced(info):

"""纯 Python 回退搜索 —— 覆盖常见生成模式"""

import itertools

prefix = info['known_prefix']

target = info['target_hex']

ks = info['ks']

mask = info['p4_mask']

cmpv = info['p4_cmp']

full = os.environ.get('CHARSET', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')

suffix_sets = ['ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_', full]

def cond(s):

a, b, c, d = [ord(x) for x in s[:4]]

o0, o1, o2, o3 = a \^ ks[0], b \^ ks[1], c \^ ks[2], d \^ ks[3]

return (((((o2 \^ (o1 &lt;&lt; 3) \^ (o0 &lt;&lt; 6)) &lt;&lt; 12) \^ (o3 &lt;&lt; 9)) & mask) == cmpv)

for suf in suffix_sets:

for bcd in itertools.product(full, repeat=3):

pre4 = '_' + ''.join(bcd)

if not cond(pre4):

continue

for tail in itertools.product(suf, repeat=3):

p4 = pre4 + ''.join(tail)

flag = prefix + p4.encode() + b'}'

if hashlib.sha256(flag).hexdigest() == target:

return flag.decode()

return None

def main():

if len(sys.argv) != 2:

print(f'usage: python {Path(sys.argv[0]).name} input.apk', file=sys.stderr)

return 2

print("[*] 解析 APK 结构与提取常量...")

info = solve_parts(sys.argv[1])

print(f'[+] 架构: {info["so_name"]}')

print(f'[+] 目标SHA-256: {info["target_hex"]}')

print(f'[+] 中间片段: frag2={info["frag2"].decode()} frag3={info["frag3"].decode()} frag4={info["frag4"].decode()}')

print(f'[+] 已恢复前缀: {info["known_prefix"].decode()}')

print(f'[+] 位掩码: 0x{info["p4_mask"]:08x} / 期望: 0x{info["p4_cmp"]:08x}')

print(f'[+] RC4密钥流: {list(info["ks"])}')

print("[*] 开始闭壳搜索...")

flag = brute_with_numba(info)

if flag is None:

print("[!] numba 不可用，回退纯 Python...")

flag = brute_python_reduced(info)

if flag:

print(f'[+] FLAG = {flag}')

else:

print('[!] 未找到flag，请安装 numba/numpy 或扩展字符集。')

return 1

return 0

if __name__ == '__main__':

raise SystemExit(main())

```

---

## 运行结果

```

[*] 解析 APK 结构与提取常量...

[+] 架构: lib/x86_64/libnative-verify.so

[+] 目标SHA-256: c6f81b343cb4dc69b6a62e5af71541119c861658c72a1167ad539cf5422f4d59

[+] 中间片段: frag2=Rp4N frag3=oyzz frag4=rE

[+] 已恢复前缀: ISCC{FkJVk55_PfVw_v5qx

[+] 位掩码: 0x03ff0000 / 期望: 0x02c40000

[+] RC4密钥流: [236, 72, 50, 39]

[*] 开始闭壳搜索...

[+] FLAG = ISCC{FkJVk55_PfVw_v5qx_VMg7Lk}

```

## Flag

**\`ISCC{FkJVk55_PfVw_v5qx_VMg7Lk}\`**
