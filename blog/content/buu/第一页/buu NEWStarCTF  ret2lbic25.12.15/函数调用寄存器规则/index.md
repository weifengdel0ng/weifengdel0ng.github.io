+++
title = "函数调用寄存器规则"
date = "2025-12-12"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
system
在Linux中，`system()`函数调用后，传入的参数（如`"/bin/sh"`字符串地址）通常存储在`RDI`寄存器中。
