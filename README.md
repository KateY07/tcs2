# TCS 安装与使用

主控端运行 `tcs`，被控端运行 `tcsd`。以下示例使用 Windows PowerShell；命令中的 `server` 请替换为被控端的计算机名或 IP 地址。

TCS 使用加密 TCP，支持 IPv4/IPv6，默认端口 `10122`。无需 sshd 或 .NET 运行时；生成密钥使用 OpenSSH 客户端附带的 `ssh-keygen`，执行远程指令需要被控端安装 Python。

连接被拒绝、DNS 解析失败、连接中断或参数错误时，CLI 在标准错误输出中打印 `tcs: operation failed:` 及异常详情，并以退出码 `1` 结束；可用 `$LASTEXITCODE` 判断失败。正常操作仍在标准输出中返回原有 JSON。此修复避免未处理异常触发 Native AOT 的系统崩溃弹窗，不会自动重试远程指令。

## 1. 安装（无需管理员权限）

在主控端和被控端分别双击 `tcs-manual-2026.09.26.2.exe`。

安装程序将 `tcs.exe`、`tcsd.exe` 和本说明复制到 `%LOCALAPPDATA%\TCS`，并将该目录加入当前用户的 **Path 环境变量**。重复安装不会重复添加，不覆盖其他 Path 项，不修改系统 Path。

安装包没有任何公钥、私钥或授权文件，也不生成密钥。不注册服务、不设置开机启动、不修改防火墙、不删除已有密钥。更新前先关闭正在运行的 TCS 程序。

安装后关闭所有终端窗口，重新打开 PowerShell，即可直接使用 `tcs` 和 `tcsd`。如果仍未识别命令，退出整个终端应用再打开；必要时注销并重新登录 Windows。

安装无需提权，但被控端防火墙若阻止 TCP 10122，需有权限的管理员另行放行。不要为此关闭整个防火墙。

查看命令用法：主控端运行 `tcs --help`，被控端运行 `tcsd --help`。

## 2. 分别生成密钥对

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

## 3. 放置公钥并连接

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

## 4. 上传 TXT 文件

在主控端用记事本创建 `demo.txt`，写入任意内容并保存到“文档”文件夹；也可以使用已有 TXT 文件。

在主控端运行，文件路径换成实际路径：

```powershell
tcs --host server --operation upload --file "$env:USERPROFILE\Documents\demo.txt"
```

按本文启动方式，文件保存在被控端的 `%LOCALAPPDATA%\TCS\data\uploads`。返回 JSON 中的 `saved` 给出实际文件名，名称带唯一标识，不会直接覆盖同名文件。上传只保存文件，不执行文本内容。

## 5. 执行 ping

在主控端运行以下命令，让被控端执行四次 ping，探测被控端自己的回环地址：

```powershell
tcs --host server --operation exec --script "import subprocess; r = subprocess.run(['ping.exe', '-n', '4', '127.0.0.1']); raise SystemExit(r.returncode)"
```

将 `127.0.0.1` 换成希望**从被控端**探测的 IP 或主机名即可。`--script` 接收 Python 源码，而不是直接接收 shell 命令。

返回 JSON 包含 `ExitCode`、`Stdout`、`Stderr`、`TimedOut`，请检查这些字段判断结果；默认执行超时 30 秒。

## 补充说明

- 多台被控端：将各自主机公钥保存为不同文件，例如 `.ssh\server2.pub`，连接时添加 `--server-key "$env:USERPROFILE\.ssh\server2.pub"`。
- 非默认端口：两端添加相同的 `--port` 参数。
- IPv6：`--host` 可填写 IPv6 地址，不加方括号。链路本地地址需附带**主控端本机**的接口编号，例如 `fe80::1234%14`，不要照抄被控端的接口编号。
- 旧版迁移：不会自动读取 `%LOCALAPPDATA%\TCS` 下的旧密钥。可通过文件管理器将原密钥迁移到当前用户 `.ssh` 目录，保留原身份；也可用 `--authorized-keys`、`--host-key`、`--client-key`、`--server-key` 指定。不要无意生成新身份后覆盖已信任的公钥。
