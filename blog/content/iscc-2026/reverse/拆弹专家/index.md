+++
title = "拆弹专家"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

### Reverse + 拆弹专家

解题思路：

这道题是一个 Windows 逆向题，整体形式类似“三关拆弹”，需要依次通过三个验证阶段，全部通过后程序会拼接输出最终 flag。程序逻辑比较清晰，核心在于分别逆向每一关的校验方式，然后将三段正确输入组合起来。

第一关是一个 8 字符输入验证。程序要求输入为可打印 ASCII 字符，随后会经过一个类似 2x2x2 魔方变换的自定义加密流程，包含位置置换、字节加法、PKCS\#7 填充和 Base64 编码，最后对结果做 FNV1a 哈希并与目标值比较。不过在分析对应函数时，可以直接从代码注释中看到第一关明文已经被写出，即 \`HYXHJTME\`，因此这一关不需要额外爆破，直接可得答案。

第二关会根据第一关得到的哈希值动态生成一个五元一次方程组。程序将 9 位数字输入拆成五个变量，其中第一位单独作为 \`x1\`，后面四组两位数字分别作为 \`x2\` 到 \`x5\`。接着利用第一关哈希值生成系数数组和目标值数组，再检查输入是否满足五个方程。根据代码中给出的生成规则，把第一关哈希代入后即可推出隐藏解为 \`\[0, 41, 54, 29, 66\]\`，格式化后得到第二关密码 \`041542966\`。

第三关则是一个迷宫寻路问题。程序将第二关输入转为整数，再结合第一关哈希经过计算得到随机种子，用于生成一个 4×4 的迷宫。迷宫生成方式保证从起点 \`(0,0)\` 到终点 \`(3,3)\` 一定存在路径。将生成出的迷宫矩阵跑一遍 BFS，即可得到最短通路为 \`RDRDRD\`，这就是第三关的正确输入。

最后程序会把固定前缀和三关答案依次拼接，生成最终 flag，因此只要将三段结果连起来即可得到完整答案。

Exp：

\`\`\`python

from collections import deque

pw1 = "HYXHJTME"

h = 0xEADE8205

base\_a = \[2, 3, 4, 5, 6\]

g\_a = \[base\_a\[i\] + ((h &gt;&gt; (i \* 6)) & 0x3) for i in range(5)\]

def lcg(st):

return (st \* 1664525 + 1013904223) & 0xFFFFFFFF

seed = h \^ 0x12345678

state = seed

x = \[\]

for i in range(5):

state = lcg(state)

if i == 0:

x.append(state % 10)

else:

x.append(10 + (state % 90))

pw2 = f"{x\[0\]:01d}{x\[1\]:02d}{x\[2\]:02d}{x\[3\]:02d}{x\[4\]:02d}"

maze\_seed = (int(pw2) \^ (h \* 0x9E3779B1)) & 0xFFFFFFFF

def gen\_maze(seed):

maze = \[0\] \* 16

st = seed \^ 0x9E3779B9

x, y = 0, 0

maze\[y \* 4 + x\] = 1

while not (x == 3 and y == 3):

st = lcg(st)

if x &lt; 3 and y &lt; 3:

move = 1 if (st & 1) else 2

elif x &lt; 3:

move = 1

else:

move = 2

if move == 1:

x += 1

else:

y += 1

maze\[y \* 4 + x\] = 1

return maze

def bfs(maze):

q = deque(\[(0, 0, "")\])

vis = {(0, 0)}

while q:

x, y, path = q.popleft()

if (x, y) == (3, 3):

return path

for dx, dy, ch in \[(1, 0, 'R'), (0, 1, 'D'), (-1, 0, 'L'), (0, -1, 'U')\]:

nx, ny = x + dx, y + dy

if 0 &lt;= nx &lt; 4 and 0 &lt;= ny &lt; 4 and maze\[ny \* 4 + nx\] and (nx, ny) not in vis:

vis.add((nx, ny))

q.append((nx, ny, path + ch))

pw3 = bfs(gen\_maze(maze\_seed))

print(f"ISCC{{{pw1}{pw2}{pw3}}}")

\`\`\`

Flag：

\`ISCC{HYXHJTME041542966RDRDRD}\`
