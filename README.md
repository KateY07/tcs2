# TCS 安装与使用

主控端运行 `tcs`，被控端运行 `tcsd`。以下示例使用 Windows PowerShell；命令中的 `server` 请替换为被控端的计算机名或 IP 地址。

TCS 使用加密 TCP，支持 IPv4/IPv6，默认端口 `10122`。无需 sshd 或 .NET 运行时；生成密钥使用 OpenSSH 客户端附带的 `ssh-keygen`，执行远程指令需要被控端安装 Python。

连接被拒绝、DNS 解析失败、连接中断或参数错误时，CLI 在标准错误输出中打印 `tcs: operation failed:` 及异常详情，并以退出码 `1` 结束；可用 `$LASTEXITCODE` 判断失败。正常操作仍在标准输出中返回原有 JSON。此修复避免未处理异常触发 Native AOT 的系统崩溃弹窗，不会自动重试远程指令。

## 1. 安装（无需管理员权限）

从 [GitHub Releases](https://github.com/KateY07/tcs2/releases) 下载安装包，在主控端和被控端分别双击 `tcs-manual-2026.09.26.4.exe`。ZIP 包内包含同一安装程序及本说明，另提供 ZIP 的 SHA256 校验文件。

安装程序将 `tcs.exe`、`tcsd.exe` 和本说明复制到 `%LOCALAPPDATA%\TCS`，并将该目录加入当前用户的 **Path 环境变量**。重复安装不会重复添加，不覆盖其他 Path 项，不修改系统 Path。

安装包没有任何公钥、私钥或授权文件，也不生成密钥。不注册服务、不设置开机启动、不修改防火墙、不删除已有密钥。更新前先关闭正在运行的 TCS 程序。

安装后关闭所有终端窗口，重新打开 PowerShell，即可直接使用 `tcs` 和 `tcsd`。如果仍未识别命令，退出整个终端应用再打开；必要时注销并重新登录 Windows。

安装无需提权，但被控端防火墙若阻止 TCP 10122，需有权限的管理员另行放行。不要为此关闭整个防火墙。

查看命令用法：主控端运行 `tcs --help`，被控端运行 `tcsd --help`。

## 2. 推荐流程：一次导入，首次连接核对指纹

两端安装通用包后，只需把一份纯数据配对文件从主控端传到被控端，无需传回公钥或回执文件。

主控端需要已有的无口令 OpenSSH 身份密钥，默认是 `.ssh\id_ed25519`。若没有，按下一节用 `ssh-keygen` 生成；已有密钥不要覆盖。

在主控端导出：

```powershell
tcs pairing export --output .\主控端.tcs-pair
```

命令显示主控公钥指纹。文件只包含版本、公钥和指纹，不含私钥、脚本或地址配置。导出目标若已存在会报错，不覆盖。需要选择其他私钥时加 `--client-key "私钥路径"`。

通过可信方式把文件复制到被控端，在被控端导入：

```powershell
tcsd pairing import .\主控端.tcs-pair
```

导入时核对显示的主控公钥指纹与导出端一致，输入 `yes` 才授权。程序保留已有授权和主机密钥；重复导入同一身份不会重复添加。被控端缺少主机私钥时会调用本机 `ssh-keygen` 生成，不需要手工放置 `authorized_keys`。导入完成会显示**被控端主机指纹**，留待首次连接时核对。

启动被控端并保持窗口运行：

```powershell
tcsd --data "$env:LOCALAPPDATA\TCS\data"
```

程序实际监听成功后显示端口、主机指纹和授权数量。在主控端连接（将 `server` 替换为实际地址）：

```powershell
tcs --host server --operation health
```

首次连接时，将主控端显示的**被控端指纹**与被控端屏幕或其他可信渠道提供的指纹核对，输入 `yes` 确认。确认后重新建立已认证连接，成功返回 `{"status":"ok"}`。这个流程不需要回执文件。

主控端按地址和端口保存公钥到 `.ssh\tcs_known_hosts`，之后同一地址的连接自动校验，指纹变化直接报错。IP、域名或端口不同会视为另一个连接目标，可能需重新确认。

探测连接会在人工确认前主动断开，避免核对时超时；被控端可能因此出现一次握手读取结束日志。此时尚未执行指令或上传文件，随后才是正式连接。

显式使用 `--server-key` 时仍严格验证该文件，不弹出首次信任提示。为了兼容旧部署，如果没有对应地址记录，且默认 `.ssh\tcs_host_key.pub` 存在，就继续使用该固定公钥。要为其他机器使用独立记录，可显式传入 `--known-hosts "另一个保存目录"`；目录切换意味着独立的信任配置，首次仍须核对。

非交互执行不会接受重定向的 `yes`。如已通过可信渠道核对完整指纹，可通过 `--trust-fingerprint "SHA256:..."` 提供该值：导入时是主控指纹，连接时是被控端指纹。错误指纹会拒绝，不存在“接受所有指纹”的开关。

配对文件中的指纹只用于完整性检查，不能独立证明来源；不要从同一个未经核实的文件里取得公钥和“正确指纹”就认为已核对身份。

## 3. 手动方式：分别生成密钥对

先在两端用文件管理器打开 `%USERPROFILE%`，确认其中有 `.ssh` 文件夹，没有就新建。私钥始终留在生成它的机器上，只交换以 `.pub` 结尾的公钥。

如果找不到 `ssh-keygen`，请通过 Windows 可选功能安装“OpenSSH 客户端”（不是 OpenSSH 服务器）；安装这个系统组件可能需要管理员权限。

### 被控端

在被控端 PowerShell 生成主机密钥：

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\tcs_host_key"
```

出现 `Enter passphrase` 和确认口令提示时，均直接按回车。生成：

- `%USERPROFILE%\.ssh\tcs_host_key`：被控端私钥，留在被控端。
- `%USERPROFILE%\.ssh\tcs_host_key.pub`：被控端公钥，稍后复制到主控端。

### 主控端

在主控端 PowerShell 生成客户端密钥：

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\id_ed25519"
```

口令及确认口令提示均直接按回车，生成：

- `%USERPROFILE%\.ssh\id_ed25519`：主控端私钥，留在主控端。
- `%USERPROFILE%\.ssh\id_ed25519.pub`：主控端公钥，稍后放到被控端授权列表。

**已有密钥不要覆盖。** 遇到覆盖提示时输入 `n` 取消；已有无口令 Ed25519 密钥可直接复用。当前 TCS 不支持口令加密私钥或 ssh-agent，不要为了复用而去掉原 SSH 私钥口令；应另建专用密钥，并通过 `--client-key` 指定。

主控端默认加载 `id_ed25519`，不会自动尝试 `.ssh` 下所有密钥。请保护 Windows 账户及私钥文件权限，不要将私钥放进共享目录或安装包。

## 4. 手动方式：放置公钥并连接

### 主控公钥放到被控端

1. 在主控端，用记事本打开 `%USERPROFILE%\.ssh\id_ed25519.pub`，复制完整的一行公钥，包括开头的 `ssh-ed25519`。
2. 在被控端，用文件管理器打开 `%USERPROFILE%\.ssh`，找到 `authorized_keys`，用记事本打开。
3. 如果没有该文件，新建一个名为 `authorized_keys` 的文件，注意**没有 `.txt` 扩展名**。可先在文件管理器中开启“文件扩展名”显示。
4. 将主控公钥粘贴为单独一行。已有其他公钥时，在末尾另起一行追加，不覆盖已有内容；同一个公钥不必重复添加。
5. 保存为 UTF-8 文本。不要加引号、Markdown 标记或把一条公钥手动拆成多行。

也可通过 U 盘或已确认身份的远程桌面传递公钥文件。若被控端还没有 `authorized_keys`，可直接将主控端的 `.pub` 文件复制过去并重命名为 `authorized_keys`。

`tcsd` 启动时读取授权列表，修改后需重启。被授权的主控端可执行被控端当前用户权限内的指令。

### 被控端公钥放到主控端

通过可信方式，将被控端的 `%USERPROFILE%\.ssh\tcs_host_key.pub` 复制到主控端的同名位置：

```text
%USERPROFILE%\.ssh\tcs_host_key.pub
```

此文件用于确认连接到正确的被控端。目标文件已存在时，先确认是否属于同一台被控端，不要盲目覆盖。可在两端分别查看此公钥的指纹，通过可信渠道确认一致：

```powershell
ssh-keygen -lf "$env:USERPROFILE\.ssh\tcs_host_key.pub" -E sha256
```

总结：主控公钥进入被控端的 `authorized_keys`；被控端公钥回到主控端的 `tcs_host_key.pub`；双方私钥均不移动。

### 启动被控端

在被控端 PowerShell 中启动：

```powershell
tcsd --data "$env:LOCALAPPDATA\TCS\data"
```

保持窗口运行，Ctrl+C 停止；重启电脑后需再次手动启动。运行指令时，程序默认使用 PATH 中的 `python`。若 Python 不在 PATH，可指定真实路径，例如：

```powershell
tcsd --data "$env:LOCALAPPDATA\TCS\data" --python "C:\Python314\python.exe"
```

示例 Python 路径须替换为实际安装路径。

### 主控端连接测试

```powershell
tcs --host server --operation health
```

成功返回 `{"status":"ok"}`。每条命令自动连接并认证，无需先登录。Ping、远程桌面成功不等于 TCP 10122 可达，还需确认被控端程序正在运行、端口未被阻止。

## 5. 上传 TXT 文件

在主控端用记事本创建 `demo.txt`，写入任意内容并保存到“文档”文件夹；也可以使用已有 TXT 文件。

在主控端运行，文件路径换成实际路径：

```powershell
tcs --host server --operation upload --file "$env:USERPROFILE\Documents\demo.txt"
```

按本文启动方式，文件保存在被控端的 `%LOCALAPPDATA%\TCS\data\uploads`。返回 JSON 中的 `saved` 给出实际文件名，名称带唯一标识，不会直接覆盖同名文件。上传只保存文件，不执行文本内容。

## 6. 执行 ping

在主控端运行以下命令，让被控端执行四次 ping，探测被控端自己的回环地址：

```powershell
tcs --host server --operation exec --script "import subprocess; r = subprocess.run(['ping.exe', '-n', '4', '127.0.0.1']); raise SystemExit(r.returncode)"
```

将 `127.0.0.1` 换成希望**从被控端**探测的 IP 或主机名即可。`--script` 接收 Python 源码，而不是直接接收 shell 命令。

返回 JSON 包含 `ExitCode`、`Stdout`、`Stderr`、`TimedOut`，请检查这些字段判断结果；默认执行超时 30 秒。

## 7. 双机实测示例

2026-09-26，已在被控端 `alipc` 验证新版连接流程。以下名称仅为实测示例，使用时替换为自己的被控端地址。

被控端导入主控公钥并启动后，主控端以通过可信渠道核对的完整主机指纹完成首次连接，返回：

```json
{"status":"ok"}
```

随后不再指定指纹，直接读取机器名和 Python 版本：

```powershell
tcs --host alipc --operation exec --script "import platform; print(platform.node()); print(platform.python_version())"
```

实际输出：

```json
{"ExitCode":0,"Stdout":"alipc\r\n3.14.4\r\n","Stderr":"","TimedOut":false}
```

此结果验证了首次固定公钥后可直接连接，不需要回执文件。每台被控端的指纹不同，必须核对自己的被控端指纹，不能复制其他机器的指纹。另已通过本机 IPv4/IPv6、Python 执行、上传完整性及配对安全回归测试；本次双机实测不包含远程上传。

## 补充说明

- 多台被控端：分别导入同一主控的配对文件，首次连接各自核对指纹，程序按地址和端口保存身份。也可手动保存不同公钥文件，并用 `--server-key` 显式指定；旧固定公钥的兼容规则见第 2 节。
- 非默认端口：两端添加相同的 `--port` 参数。
- IPv6：`--host` 可填写 IPv6 地址，不加方括号。链路本地地址需附带**主控端本机**的接口编号，例如 `fe80::1234%14`，不要照抄被控端的接口编号。
- 旧版迁移：不会自动读取 `%LOCALAPPDATA%\TCS` 下的旧密钥。可通过文件管理器将原密钥迁移到当前用户 `.ssh` 目录，保留原身份；也可用 `--authorized-keys`、`--host-key`、`--client-key`、`--server-key` 指定。不要无意生成新身份后覆盖已信任的公钥。
