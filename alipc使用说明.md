# TCS 使用说明：连接和使用 alipc

本文针对已部署的 Windows x64 Native AOT 版本。主控端是本机 `superpc`，被控端是 `alipc`。日常使用端口为 **10122**；`3388` 仅用于此前排查。

已实际通过 TCS 在 `alipc:10122` 执行 Python 版本查询：Python **3.14.4，64 位 AMD64**，远程退出码为 `0`，无错误、无超时。

## 1. 文件和运行方式

主控端运行 `tcs.exe`；被控端运行 `tcsd.exe`。这两个程序不需要安装 .NET Runtime 或 sshd。执行 Python 脚本需要被控端安装可用的 Python。

主控端现有文件：

| 用途 | 路径 |
|---|---|
| 客户端 | `D:\1\tcs\_package\tcs-aot-win-x64\tcs.exe` |
| 主控私钥 | `C:\Users\arosa\.ssh\id_ed25519` |
| 已确认的 alipc 主机公钥 | `D:\1\tcs\_package\alipc-3388.pub` |

公钥文件名中的 `3388` 是首次确认时使用的端口。它保存的是 alipc 的主机公钥；当前 `10122` 实例使用相同的主机密钥，因此继续使用此文件，且已实测验证通过。

被控端 v6 安装目录为 `%LOCALAPPDATA%\TCS`，当前对应 `C:\Users\me\AppData\Local\TCS`：

| 文件或目录 | 用途 |
|---|---|
| `tcsd.exe` | 被控端程序 |
| `start-tcsd.cmd` | 手动启动入口 |
| `controller.pub` | 安装包携带的主控公钥 |
| `authorized_keys` | 被控端接受的主控公钥列表 |
| `tcs_host_key` / `tcs_host_key.pub` | 被控端自身的私钥与公钥 |
| `data\uploads` | 上传文件保存目录 |
| `data\tcs-audit.log` | 执行和上传操作的审计记录 |

v6 安装包仅复制文件，不提权、不创建服务或计划任务、不配置防火墙。首次运行启动脚本时，会通过 `ssh-keygen` 生成缺失的主机密钥，并在 `authorized_keys` 不存在时从 `controller.pub` 初始化授权文件。

## 2. 在 alipc 上启动

在目标机 PowerShell 执行：

```powershell
& "$env:LOCALAPPDATA\TCS\start-tcsd.cmd"
```

保持该窗口运行。按 `Ctrl+C` 停止；批处理询问是否终止时输入 `Y`。本模式不会在重启后自动运行，需要再次手动启动。

启动脚本显示的监听提示是在调用程序前输出的。要确认实际监听，可在目标机另开一个 PowerShell 窗口执行：

```powershell
Get-NetTCPConnection -LocalPort 10122 -State Listen
```

正常可见 `LocalAddress = ::`、`State = Listen`。程序使用 IPv6 Any 加 DualMode，同一端口同时接受 IPv4 和 IPv6。

## 3. 在主控端配置本次连接

打开主控端 PowerShell，执行以下三行。后续示例在这个窗口中运行：

```powershell
$Tcs = 'D:\1\tcs\_package\tcs-aot-win-x64\tcs.exe'
$AlipcKey = 'D:\1\tcs\_package\alipc-3388.pub'
$Connection = @('--host', 'alipc', '--port', '10122', '--client-key', "$env:USERPROFILE\.ssh\id_ed25519", '--server-key', $AlipcKey)
```

客户端默认读取 `%USERPROFILE%\.ssh\id_ed25519`。这里显式列出密钥参数，确保连接使用已经授权的主控密钥和已经确认的目标机公钥。

若需要按已实测的 IPv6 地址连接，将第三行替换为：

```powershell
$Connection = @('--host', 'fe80::ecd2:18b:b9f9:f65%14', '--port', '10122', '--client-key', "$env:USERPROFILE\.ssh\id_ed25519", '--server-key', $AlipcKey)
```

`%14` 是当前主控机的本地网络接口索引。alipc 自身对应接口索引是 `%5`，不能把目标机的 `%5` 用作主控机的接口号。换网卡或换主控机后，应重新确认本地接口索引。

## 4. 健康检查和读取 Python 版本

健康检查：

```powershell
& $Tcs @Connection --operation health
```

预期返回：

```json
{"status":"ok"}
```

读取目标机 Python 版本：

```powershell
& $Tcs @Connection --operation exec --script 'import sys; print(sys.version)'
```

`exec` 接收的是 **Python 源代码**，不是 PowerShell 或 CMD 命令。返回值包含 `ExitCode`、`Stdout`、`Stderr` 和 `TimedOut`。

如果只想显示远程输出：

```powershell
$Result = (& $Tcs @Connection --operation exec --script 'import sys; print(sys.version)') | ConvertFrom-Json
$Result.Stdout
$Result.Stderr
$Result.ExitCode
$Result.TimedOut
```

成功标准为 `ExitCode = 0` 且 `TimedOut = false`。客户端进程成功退出不代表远程 Python 成功，必须检查返回 JSON 中的状态。

## 5. 获取系统信息和运行脚本文件

读取主机名、系统版本和 Python 版本：

```powershell
& $Tcs @Connection --operation exec --script 'import platform; print(platform.node()); print(platform.platform()); print(platform.python_version())'
```

执行主控端现有的 Python 文件，例如当前目录的 `check.py`：

```powershell
$Script = Get-Content -LiteralPath '.\check.py' -Raw -Encoding UTF8
$Encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
& $Tcs @Connection --operation exec --script-base64 $Encoded
```

Base64 参数适合多行、带引号或中文的脚本，减少命令行转义问题。脚本在目标机作为临时 Python 文件执行，完成后删除；不会自动上传它引用的其他本地文件。大型脚本还会受到 Windows 命令行长度限制。

目前 CLI 的执行请求使用默认 30 秒超时，没有单独暴露超时参数。执行身份是启动 `tcsd` 的用户，当前为 `me`。

## 6. 上传文件

上传主控端当前目录中的 `test.zip`：

```powershell
& $Tcs @Connection --operation upload --file '.\test.zip'
```

响应的 `saved` 数组给出目标机保存的文件名。程序会添加时间和随机标识，避免同名覆盖，不会自动解压或执行上传文件。

用默认启动脚本运行时，文件保存在目标机：

```text
C:\Users\me\AppData\Local\TCS\data\uploads\
```

当前客户端和服务端会把上传请求缓存在内存中，建议先使用小文件验证，尚不能按大型文件流式传输工具使用。并发请求使用各自独立的 TCP 连接。

## 7. 密钥与首次信任

两种公钥用途不同：

- 主控公钥在目标机 `authorized_keys` 中，授权主控端执行操作。对应私钥留在主控端。
- 目标机公钥通过主控端的 `--server-key` 指定，用于核对目标机身份。目标机私钥留在目标机。

本次用户已确认的 alipc 主机指纹为：

```text
SHA256:wLwb/QS3jo9uC2g60/KlJcg83XlLenLzxlPtdIsqpPQ
```

在目标机核对：

```powershell
ssh-keygen -lf "$env:LOCALAPPDATA\TCS\tcs_host_key.pub" -E sha256
```

当前客户端不会自动扫描所有 SSH 密钥、读取 SSH config 或弹出首次信任提示，也不会自动保存 known_hosts。连接其他被控机时，需先可信获取并核对其公钥，然后用对应的 `--server-key` 文件连接。

直接运行不带密钥参数的 `tcsd.exe` 默认读取用户 `.ssh` 目录；本文的安装启动脚本则显式使用 `%LOCALAPPDATA%\TCS` 下的密钥和数据。两种启动方式的路径不要混用。

## 8. 常见问题

**端口连不上**

先核对当前实际端口。默认启动脚本使用 `10122`，之前手动运行的测试实例使用 `3388`。

在主控端普通 PowerShell 测试：

```powershell
Test-NetConnection alipc -Port 10122
```

本次排查曾发现自动化沙箱拒绝 TCP 访问，返回 `AccessDenied`；在沙箱外同一目标可连接。因此不能仅凭沙箱中的失败结果判定目标机防火墙故障。Ping 成功只验证 ICMP，不验证 TCS 握手。

若目标机确有防火墙限制，应按其管理策略允许 TCP 10122 入站；无需为了 TCS 关闭整个防火墙。

**提示 `Python was not found`，退出码 9009**

目标机 `python` 可能指向 Windows Store 占位程序。停止 tcsd 后，在目标机同一窗口指定已经安装的 Python，再启动：

```powershell
$env:TCS_PYTHON_EXE = "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe"
& "$env:LOCALAPPDATA\TCS\start-tcsd.cmd"
```

上述是本次在 alipc 实际查询到的 Python 路径。环境变量设置后需要重新启动 tcsd 才能生效。

**提示 `server host-key fingerprint mismatch`**

目标机密钥与 `--server-key` 不一致。先确认连接主机和目标机指纹，核实是否重新生成过主机密钥，再更新已保存的公钥。

**日志出现 `Attempted to read past the end of the stream`**

纯 TCP 探测连接后不发送 TCS 握手就关闭连接，会出现该日志。健康检查应使用 `tcs.exe --operation health`。该日志本身不能证明是哪台机器发起连接。

**看不到服务或计划任务**

v6 使用手动启动模式，这是预期行为。保持启动窗口运行即可，不需要查询 `schtasks`。
