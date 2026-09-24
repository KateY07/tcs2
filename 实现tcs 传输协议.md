# TCS/1 传输协议规范

版本：`TCS/1`

双方必须按照本规范实现。任何字段、密钥用途、握手顺序或加密边界的变化都必须使用新的协议版本。

## 1. 范围与边界

协议运行在裸 TCP 之上，负责：

- 使用 OpenSSH 格式的密钥完成双向身份认证；
- 协商每条连接独立的临时会话密钥；
- 使用 AEAD 加密和认证 HTTP 请求/响应字节流；
- 支持 `/v1/health`、`/v1/exec` 和 `/v1/upload` HTTP endpoint；
- 支持多个并发 HTTP 流；
- 支持大文件流式上传，不把完整文件读入内存。

协议不依赖：

- 系统 `sshd`；
- TLS 或 X.509 证书；
- SSH transport、SSH channel 或 SSH subsystem；
- 预共享对称密钥；
- 自定义密码算法实现。

HTTP 请求和响应字节流封装在 TCS 加密帧中。

## 2. 密钥与身份

### 2.1 主控端身份密钥

主控端使用 OpenSSH 私钥，支持以下公钥类型：

- `ssh-ed25519`；
- `ecdsa-sha2-nistp256`、`ecdsa-sha2-nistp384`、`ecdsa-sha2-nistp521`；
- RSA 公钥，签名必须使用 `rsa-sha2-256` 或 `rsa-sha2-512`。

禁止使用 `ssh-dss` 和 SHA-1 `ssh-rsa` 签名。

主控端私钥只能存在于主控端，绝不能复制到被控端、写入日志或发送到网络。

### 2.2 被控端授权文件

被控端使用标准 OpenSSH `authorized_keys` 文本格式保存主控端公钥，每行一个公钥。

只接受没有授权选项的标准公钥行；包含 `command=`, `from=`, `restrict` 等 OpenSSH 选项的行必须拒绝。

授权判断使用 OpenSSH 公钥 blob 的 SHA-256 指纹。注释不参与指纹计算。

### 2.3 被控端身份密钥

被控端必须拥有一对稳定的服务端身份密钥：

```text
server_host_key       私钥，只保存在被控端
server_host_key.pub   公钥，预置到主控端
```

主控端必须在握手时校验服务端公钥指纹。指纹变化必须中止连接，不能自动接受新指纹。

服务端身份密钥也使用 OpenSSH 公钥格式。它与主控端授权密钥分开管理，不得混用。

## 3. 密码套件

TCS/1 固定使用：

```text
密钥交换：X25519
密钥派生：HKDF-SHA256
数据加密：ChaCha20-Poly1305
哈希：SHA-256
```

实现必须调用成熟密码库，不得自行实现上述算法。

密码套件编号字段的唯一允许值为：

```text
0x0001 = X25519 + HKDF-SHA256 + ChaCha20-Poly1305
```

收到未知或不允许的套件编号时必须拒绝握手。

## 4. TCP 基本规则

- 所有整数使用大端序。
- TCP 是字节流，单次 `Read` 不对应一个协议消息；实现必须循环读取直到取得完整字段。
- TCP 半关闭、异常关闭、读取超时和写入失败都视为连接失败。
- 握手阶段读取超时：10 秒。
- 握手完成后无数据读取超时：60 秒；正在上传或执行时可由请求级超时覆盖。
- 单帧最大密文载荷：64 KiB。
- 单个 HTTP 流的总大小不设固定上限，但必须流式处理并受磁盘、请求超时和系统资源限制约束。
- 握手消息最大长度：64 KiB。

## 5. 握手流程

握手必须在任何 HTTP 数据发送之前完成。所有握手消息使用明文握手帧，但不会承载 HTTP 内容或私钥材料。

### 5.1 ClientHello

主控端发送：

```text
magic              4 bytes   ASCII "TCS1"
messageType        1 byte    0x01
version            u16       0x0001
cipherSuite        u16       0x0001
clientKeyBlobLen   u32
clientKeyBlob      bytes     OpenSSH 公钥 blob
clientEphemeral    32 bytes  X25519 公钥
clientNonce        32 bytes  随机数
```

服务端必须先确认 `clientKeyBlob` 存在于 `authorized_keys`，再继续握手。

### 5.2 ServerHello

服务端发送：

```text
magic              4 bytes   ASCII "TCS1"
messageType        1 byte    0x02
version            u16       0x0001
cipherSuite        u16       0x0001
serverKeyBlobLen   u32
serverKeyBlob      bytes     服务端 OpenSSH 公钥 blob
serverEphemeral    32 bytes  X25519 公钥
serverNonce        32 bytes  随机数
signatureLen       u32
serverSignature    bytes
```

`ServerHelloUnsignedBytes` 定义为从 `magic` 开始、到 `serverNonce` 结束的完整字节序列，不包含 `signatureLen` 和 `serverSignature` 字段。

`serverSignature` 使用服务端稳定私钥签名以下严格拼接的字节：

```text
SHA256("TCS1/server" || ClientHelloBytes || ServerHelloUnsignedBytes)
```

主控端必须验证：

1. `magic`、版本和密码套件正确；
2. 服务端公钥指纹等于预置指纹；
3. 服务端签名有效；
4. nonce 和临时公钥长度正确且非全零。

### 5.3 ClientAuth

主控端发送：

```text
magic              4 bytes   ASCII "TCS1"
messageType        1 byte    0x03
signatureLen       u32
clientSignature    bytes
```

`clientSignature` 使用主控端 OpenSSH 私钥签名。`ServerHelloBytes` 指完整的 ServerHello 字节序列，包括签名长度和签名：

```text
SHA256("TCS1/client" || ClientHelloBytes || ServerHelloBytes)
```

服务端必须使用 `authorized_keys` 中匹配的公钥验证签名。签名失败时不得进入加密数据阶段。

### 5.4 会话密钥派生

双方计算：

```text
sharedSecret = X25519(localEphemeralPrivate, remoteEphemeralPublic)
transcript   = SHA256(ClientHelloBytes || ServerHelloBytes || ClientAuthBytes)
keyMaterial  = HKDF-SHA256(
                 ikm = sharedSecret,
                 salt = transcript,
                 info = "TCS1/session",
                 length = 72)
```

`keyMaterial` 的布局为：

```text
0..31    clientToServerKey
32..63   serverToClientKey
64..67   clientToServerDirectionPrefix
68..71   serverToClientDirectionPrefix
```

双方不得交换或复用发送密钥或方向前缀。

握手完成后，临时私钥、握手明文和签名缓存必须及时清理；审计日志只能记录指纹、版本、结果和错误码，不能记录握手密钥材料。

## 6. 加密帧

握手完成后，所有数据使用加密帧传输。

### 6.1 帧格式

```text
frameLength       u32       后续帧头和 ciphertext 的总长度
frameType         u8
flags             u8
streamId          u32
sequence          u64
ciphertext        bytes     明文 + 16-byte Poly1305 tag
```

`frameLength` 必须在 `1` 到 `64 KiB + header` 范围内。超出范围必须立即关闭连接。

帧头作为 AEAD 的 associated data，不单独加密但必须认证。

nonce 固定为：

```text
directionPrefix   4 bytes   从 keyMaterial 派生的方向前缀
sequence          8 bytes
```

同一方向、同一会话中 `sequence` 不得重复；从零开始递增。发现重复、倒退或溢出必须关闭连接。

### 6.2 帧类型

```text
0x10 OPEN       开始一个 HTTP 流
0x11 DATA       HTTP 字节片段
0x12 END        发送方向结束
0x13 RESET      中止 HTTP 流
0x14 ERROR      协议或请求错误
0x15 PING       保活
0x16 PONG       保活响应
```

客户端创建的 `streamId` 使用奇数，服务端创建的使用偶数。HTTP 流只能由客户端创建。

### 6.3 OPEN

`OPEN` 明文内容：

```text
httpVersion     u8        0x01 表示 HTTP/1.1 字节流
requestFlags    u8        预留，必须为 0
```

随后同一 `streamId` 的 `DATA` 帧中传输完整 HTTP 请求字节流，最后使用 `END` 表示请求发送完成。

### 6.4 DATA

`DATA` 内容是原始 HTTP/1.1 字节，不得修改 HTTP 方法、路径、头、JSON 或 multipart 格式。

实现必须支持任意位置分割 HTTP 请求，包括：

- 请求行中间；
- 头字段中间；
- JSON 中间；
- multipart boundary 中间；
- 文件内容中间。

服务端不得等待整个请求体进入内存后再处理上传；应将数据流交给 HTTP 处理层或等价的流式适配层。

## 7. HTTP 流与并发

每个 `streamId` 对应一个独立的 HTTP 请求/响应对：

```text
OPEN(client → server)
DATA(client → server) ...
END(client → server)
DATA(server → client) ...
END(server → client)
```

多个流可以在同一个 TCP 连接上交错传输。服务端必须保证：

- 不同流的 HTTP 字节不会串联；
- 不同 `/v1/exec` 请求的 stdout/stderr 不会串流；
- 一个流失败不会自动中止其他流；
- 连接级认证失败才会关闭整个连接；
- 单个请求级超时只中止对应流和对应子进程。

客户端可以使用连接池，每条连接可以承载一个或多个流。

## 8. 错误处理

`ERROR` 明文内容：

```text
errorCode       u16
messageLen      u16
message         UTF-8 bytes
```

错误码：

```text
0x0001 INVALID_VERSION
0x0002 INVALID_CIPHER
0x0003 INVALID_KEY
0x0004 UNAUTHORIZED_KEY
0x0005 INVALID_SIGNATURE
0x0006 INVALID_FRAME
0x0007 REPLAY_DETECTED
0x0008 FRAME_TOO_LARGE
0x0009 STREAM_LIMIT
0x000A REQUEST_TIMEOUT
0x000B INTERNAL_ERROR
```

握手阶段错误必须关闭连接。数据阶段的流错误优先使用 `RESET` 或 `ERROR` 终止对应流；无法确定连接状态时关闭整个连接。
