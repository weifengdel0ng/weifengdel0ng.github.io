+++
title = "return2libc"
date = "2025-12-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
**payload:** padding1 + address of system() + padding2 + address of “/bin/sh”

	padding1 处的数据可以随意填充（注意不要包含 “\x00”  , 否则向程序传入溢出数据时会造成截断）
	长度应该刚好覆盖函数的基地址

	padding2 处的数据长度为4（32位机），对应调用 system() 时的返回地址。
	因为我们在这里只需要打开 shell 就可以，并不关心从 shell 退出之后的行为，所以 padding2 的内容可以随意填充。


- `p64(elf.got['puts'])`: 参数1 - puts函数的GOT表地址
    
- `p64(elf.sym['puts'])`: 调用puts函数，泄露GOT表中的真实地址
    
- `p64(elf.sym['main'])`: 返回到main函数，以便二次利用
