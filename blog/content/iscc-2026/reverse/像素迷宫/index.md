+++
title = "像素迷宫"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

### Reverse +像素迷宫

解题思路：

题目给出的文件是一个 64 位 Windows 控制台程序，运行后会提示输入 flag。通过字符串信息可以先确定程序会校验 \`ISCC{}\` 格式，并且程序中还出现了 \`PixelMaze1.cpp\`、\`Correct!\`、\`Incorrect!\` 等关键字，说明题目没有做额外混淆，核心就是分析内部路径验证逻辑。

主函数流程比较直接，程序先读取用户输入，然后调用 \`extractPath()\` 提取花括号中的内容。如果输入不满足 \`ISCC{...}\` 格式，或者中间内容为空，就直接判错。进一步分析 \`extractPath()\` 可以发现，它会逐字符过滤，只保留 \`E\`、\`N\`、\`S\`、\`W\` 这四个方向字符，因此可以判断花括号内部实际是一条迷宫路径。

继续分析 \`validatePath()\` 和 \`isValidMove()\` 后，可以确认程序在一个 10×10 的迷宫中模拟移动。起点是 \`(0,0)\`，终点是 \`(9,9)\`，每读入一个方向字符，就检查当前位置是否允许向该方向移动。每个格子的通路信息并不是明文存储，而是通过 \`getDecryptedPixel()\` 从三段数据中取值后再异或 \`0x7f\` 解密得到。解密后的每个字节低四位分别表示四个方向是否可通行，其中 bit0 对应 \`E\`，bit1 对应 \`W\`，bit2 对应 \`S\`，bit3 对应 \`N\`。

把三段加密数据全部取出并异或还原后，就能得到完整的 10×10 迷宫图。接下来从起点 \`(0,0)\` 出发，对迷宫进行 BFS 搜索，查找到终点 \`(9,9)\` 的一条合法路径。最终求得的方向串长度为 52，内容为 \`SSENEEESENNEESWSESSSWNNWWWNWSSSWWSSEENESEENEESWSEEES\`。将其放入 \`ISCC{}\` 中即可得到最终 flag。

Exp：

```python

from collections import deque

encrypted_part1 = [

0x7b, 0x7e, 0xce, 0xbc, 0x2d, 0xae, 0xae, 0x8b, 0x5e, 0xcb,

0x1b, 0x2e, 0xce, 0x7e, 0x8b, 0xc7, 0x5b, 0xfd, 0xcb, 0x89,

0xde, 0x07, 0xfb, 0x8d, 0x8e, 0x57, 0x9e, 0xfb, 0xa3, 0xb6,

]

encrypted_part2 = [

0x9a, 0x8b, 0x5b, 0xb7, 0xdd, 0x7d, 0xed, 0x6b, 0x87, 0x17,

0xd6, 0x85, 0x0b, 0x4a, 0xdb, 0xf9, 0x97, 0xfb, 0x36, 0x4c,

0xfb, 0xad, 0x1d, 0x87, 0xe3, 0xa5, 0xe7, 0xdd, 0x0e, 0xad,

0x0b, 0x09, 0xfe, 0x9b, 0xc7, 0xce, 0x7e, 0xeb, 0x5a, 0xbd,

]

stack_values = [

0xbe, 0xbe, 0x37, 0x2e, 0x7e, 0xb7, 0x8b, 0x1d, 0x66, 0x9d,

0x6e, 0x4a, 0x3c, 0x5a, 0x7d, 0xa9, 0x3e, 0xee, 0x2e, 0xeb,

0x76, 0xee, 0x4d, 0x0c, 0x67, 0x49, 0xad, 0x7c, 0x3d, 0x00,

]

grid = [[0] * 10 for _ in range(10)]

for y in range(10):

for x in range(10):

idx = y * 10 + x

if y &lt;= 2:

enc = encrypted_part1[idx]

elif y &lt;= 6:

enc = encrypted_part2[(y - 3) * 10 + x]

else:

enc = stack_values[(y - 7) * 10 + x]

grid[y][x] = enc \^ 0x7f

dirs = {'E': (1, 0, 0), 'W': (-1, 0, 1), 'S': (0, 1, 2), 'N': (0, -1, 3)}

def solve():

q = deque([(0, 0, "")])

vis = {(0, 0)}

while q:

x, y, path = q.popleft()

val = grid[y][x]

for d, (dx, dy, bit) in dirs.items():

if (val &gt;&gt; bit) & 1:

nx, ny = x + dx, y + dy

if 0 &lt;= nx &lt; 10 and 0 &lt;= ny &lt; 10 and (nx, ny) not in vis:

if (nx, ny) == (9, 9):

return path + d

vis.add((nx, ny))

q.append((nx, ny, path + d))

print(f"ISCC{{{solve()}}}")

```

Flag：

\`ISCC{SSENEEESENNEESWSESSSWNNWWWNWSSSWWSSEENESEENEESWSEEES}\`
