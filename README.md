# TCS 安装与使用

主控端运行 tcs，被控端运行 tcsd。使用加密 TCP，支持 IPv4/IPv6，默认端口 10122，无需 sshd 或 .NET 运行时。以下命令使用 Windows PowerShell，server 替换为被控端计算机名或可达 IP。

部署顺序：**用户生成密钥 → 安装前检查 → 安装 → 导出/导入配对文件 → 启动被控端 → 首次核对指纹 → 此后直接连接**。只传递一份纯数据配对文件，无需回执。

## 1. 固定位置

所有位置属于当前 Windows 用户，没有命令行路径覆盖选项。请使用日常运行 TCS 的账户准备密钥和安装。

| 内容 | 固定位置 |
|---|---|
| 主控私钥及公钥 | %USERPROFILE%\.ssh\id_ed25519、id_ed25519.pub |
| 被控私钥及公钥 | %USERPROFILE%\.ssh\tcs_host_key、tcs_host_key.pub |
| 被控授权列表 | %USERPROFILE%\.ssh\authorized_keys |
| 主控按地址和端口保存的信任记录 | %USERPROFILE%\.ssh\tcs_known_hosts |
| 主控兼容旧部署的固定被控公钥 | %USERPROFILE%\.ssh\tcs_host_key.pub |
| 程序 | %LOCALAPPDATA%\TCS |
| 上传文件 | %LOCALAPPDATA%\TCS\data\uploads |
| 审计日志 | %LOCALAPPDATA%\TCS\data\tcs-audit.log |

%USERPROFILE% 与 %LOCALAPPDATA% 指当前账户的系统目录，不是可自定义的 TCS 配置项。安装不修改密钥；导出、导入和运行也不会自动生成密钥。

## 2. 安装前：用户生成密钥

只生成本机角色需要的密钥。私钥留在生成它的机器上，不要放进配对文件、安装包或共享目录。已有固定位置的密钥对，保留原文件，不重复生成。

生成命令依赖 ssh-keygen。找不到时，通过 Windows 可选功能安装“OpenSSH 客户端”，不需要 OpenSSH 服务器；安装此系统组件可能需要管理员权限。

当前只支持无口令 OpenSSH 私钥，不支持 ssh-agent 或口令解锁。不要为复用擅自去掉原密钥口令。若固定位置已有带口令或不可用的私钥，请先妥善备份并人工规划迁移，安装程序不会覆盖或修复它。

### 主控端

在 PowerShell 复制运行：

~~~powershell
$ErrorActionPreference = 'Stop'
$tcsKey = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
New-Item -ItemType Directory -Force (Split-Path $tcsKey) | Out-Null
if ((Test-Path -LiteralPath $tcsKey) -or (Test-Path -LiteralPath ($tcsKey + '.pub'))) {
    throw "密钥或公钥已存在，请检查原密钥对，不要覆盖：$tcsKey"
} else {
    ssh-keygen -t ed25519 -f $tcsKey
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen 生成失败' }
}
~~~

出现口令及确认口令提示时，两次直接按回车。生成 id_ed25519 和 id_ed25519.pub。

### 被控端

在 PowerShell 复制运行：

~~~powershell
$ErrorActionPreference = 'Stop'
$tcsKey = Join-Path $env:USERPROFILE '.ssh\tcs_host_key'
New-Item -ItemType Directory -Force (Split-Path $tcsKey) | Out-Null
if ((Test-Path -LiteralPath $tcsKey) -or (Test-Path -LiteralPath ($tcsKey + '.pub'))) {
    throw "密钥或公钥已存在，请检查原密钥对，不要覆盖：$tcsKey"
} else {
    ssh-keygen -t ed25519 -f $tcsKey
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen 生成失败' }
}
~~~

口令提示两次直接回车。生成 tcs_host_key 和 tcs_host_key.pub。此时不需要手工创建 authorized_keys，后续导入负责追加授权。

只有可用私钥即可安装。TCS 从私钥推导本机公钥，不读取、不检查、不修改同名 .pub；它缺失、不匹配或损坏均不影响本机身份使用，也不会因此警告。只有公钥但缺少私钥时仍停止，请恢复原私钥，不要生成另一份身份覆盖已有文件。对端公钥授权和主机信任记录不属于本机公钥副本，仍然严格读取和校验。

## 3. 安装（无需管理员权限）

从 [GitHub Releases](https://github.com/KateY07/tcs2/releases) 获取发布包；当前版本安装包为 tcs-manual-2026.09.26.7.exe。两端分别双击安装程序，选择 C（主控端）或 S（被控端）。选择决定检查哪个私钥，同一安装包包含两个程序。

安装程序只检查固定位置的私钥是否可读取、格式及签名是否可用，公钥和指纹直接从私钥推导。私钥缺失、损坏或带口令时停止，显示错误和供全新用户复制的生成脚本；已有身份应恢复原私钥。不会继续复制程序或修改用户 Path，也不会自动执行生成命令。不要求同名 .pub 存在。

检查通过后，安装到 %LOCALAPPDATA%\TCS 并去重加入当前用户 Path。不携带密钥、不注册服务、不设置开机启动、不修改防火墙。更新前关闭正在运行的 TCS。

安装后关闭整个终端应用并重新打开 PowerShell，运行 tcs --help 或 tcsd --help。仍不识别命令时可注销再登录刷新环境变量。

安装无需提权不代表网络一定可达。被控端 TCP 10122 若被防火墙阻止，需要有权限的管理员另行放行，不要关闭整个防火墙。

## 4. 导出并导入配对文件

主控端执行：

~~~powershell
tcs pairing export --output .\主控端.tcs-pair
~~~

显示主控公钥指纹和文件完整路径。文件只含版本、公钥与指纹，不含私钥或脚本；目标已存在时拒绝覆盖。

通过可信方式将文件复制到被控端。终端切换到文件所在目录，或在命令中使用配对文件完整路径：

~~~powershell
tcsd pairing import .\主控端.tcs-pair
~~~

核对显示的主控指纹与导出端一致，输入 yes。程序向固定的 authorized_keys 追加公钥，保留已有授权和主机身份；重复导入不重复添加。缺少被控端密钥时直接失败，**不会调用 ssh-keygen**。

导入完成显示被控端主机指纹，留待首次连接核对，无需传回文件。授权变更后，已运行的 tcsd 需要重启加载。

配对文件内指纹只能检查内容一致性，不能独立证明来源。核对依据应来自可信渠道，而非同一个未经核实的文件。

## 5. 启动和连接

被控端只需执行：

~~~powershell
tcsd
~~~

显示双栈监听端口、主机指纹、授权数量和固定数据目录。保持窗口运行，Ctrl+C 停止；重启电脑后需手动再次启动。**不再使用或接受 --data。**

主控端执行（默认就是健康检查）：

~~~powershell
tcs server health
~~~

首次连接先验证被控端握手签名，再显示指纹。与被控端屏幕或其他可信渠道提供的指纹核对，输入 yes，保存后重新建立认证连接，成功返回：

~~~json
{"status":"ok"}
~~~

相同地址和端口以后自动校验，不再询问。指纹变化拒绝连接，不自动覆盖。改用计算机名、IP 或端口视为不同目标，可能重新要求确认。

首次探测在认证前主动结束连接。被控端显示“可能为首次指纹探测或主动取消；未认证，未执行指令或上传”，这是状态说明，不代表认证成功；认证消息截断、签名错误仍按失败记录。

### 旧固定公钥生效

没有该目标独立记录，但主控端 .ssh\tcs_host_key.pub 存在时，程序明确显示：

~~~text
旧固定公钥正在生效：完整路径
固定指纹：SHA256:...
使用旧固定公钥严格校验，因此不会询问首次确认。
~~~

这是兼容旧部署，不是跳过校验。目标不匹配时连接失败；先通过可信渠道确认旧文件用途，再人工备份、迁移信任配置，不要为消除报错直接删除它。同一账户兼任两种角色时，本机 tcs_host_key.pub 也会命中此兼容规则，不能把本机公钥误当成另一台机器的身份。

非交互执行不接受重定向的 yes。已独立核对完整指纹时可用 --trust-fingerprint "SHA256:..."；导入时填主控指纹，连接时填被控端指纹。此参数不能覆盖已有信任。

## 6. 上传 TXT 文件

用记事本创建 demo.txt，在主控端执行（路径换成实际文件）：

~~~powershell
tcs server upload "$env:USERPROFILE\Documents\demo.txt"
~~~

固定保存到被控端 %LOCALAPPDATA%\TCS\data\uploads；响应 saved 给出实际文件名。名称带唯一标识，不直接覆盖同名文件。上传不执行内容。

## 7. 执行 ping

执行远程指令要求被控端安装 Python。健康检查和上传成功不代表 Python 可用。如果不在 PATH，可用 tcsd --python "实际解释器完整路径" 启动；密钥和数据位置仍固定。

主控端执行，让被控端 ping 自己的回环地址四次：

~~~powershell
tcs server exec "import subprocess; r = subprocess.run(['ping.exe', '-n', '4', '127.0.0.1']); raise SystemExit(r.returncode)"
~~~

exec 的内容是 Python 源码，不是 shell 命令。响应含 ExitCode、Stdout、Stderr、TimedOut，需检查字段判断结果；默认执行超时 30 秒。

也可以执行主控端已有的 Python 文件（UTF-8，可带 BOM）：

~~~powershell
tcs server exec --file "test.py"
~~~

文件路径相对于主控终端当前目录，含空格时加引号。仅发送源码在被控端执行，不自动上传依赖、设置脚本所在目录或传递脚本参数；被控端仍须安装相应 Python 依赖。缺失文件、无效 UTF-8 和冲突参数在连接前报错。

将 server 替换为被控端名称或 IP，例如 `tcs alipc health`。省略操作的 `tcs alipc` 也是健康检查。非默认端口可写 `tcs alipc health --port 3388`。

原有 `tcs --host server --operation health`、`--operation exec --script "print('hello')"`、`--operation upload --file .\demo.txt` 形式仍兼容。exec 的源码、`--file`、`--script-base64` 三种输入不能混用，位置参数与同名选项也不能重复指定。密钥固定路径和首次信任校验规则不变。

## 8. 故障和升级

- CLI 失败返回退出码 1，在标准错误输出给出提示并保留异常详情；正常 JSON 在标准输出。
- TCP 被拒绝：检查被控端是否运行、双方端口是否一致。Ping/RDP/共享可用不代表此端口可达。
- 对端提前关闭：核对被控端日志及主控授权，不能直接断定是防火墙；程序不自动重试远程指令。
- 密钥变化或签名失败：停止连接，通过可信渠道确认身份，不自动接受新公钥。
- 缺少 authorized_keys：先在被控端导入配对文件，再启动。
- 非默认端口：两端使用相同 --port。IPv6 地址不加方括号；链路本地地址附加主控本机接口编号，例如 fe80::1234%14。
- 从旧版升级：--data、--client-key、--host-key、--authorized-keys、--server-key、--known-hosts 均被拒绝；旧自定义位置不自动迁移。通过文件管理器核对、备份并迁移到表列固定位置，保留私钥身份，不覆盖冲突文件。旧上传和日志不自动移动。

## 9. 验证记录与开发测试

2026-09-26，上一版配对功能在被控端 alipc 实测：首次固定指纹后健康检查返回 {"status":"ok"}，后续直接执行 import platform; print(platform.node()); print(platform.python_version())，输出 alipc、3.14.4，退出码 0。这不代表新安装前检查已在 alipc 验收。

固定路径发布 CLI 不提供测试路径后门。隔离测试使用 tests/TransportHarness.csproj，它链接生产传输类，只在测试程序内接受临时路径，不进入安装包。构建该项目后，pairing_regression_test.py 和 crash_regression_test.py 接受测试程序路径；deployment_regression_test.py 接受发布程序和测试程序两个路径，检查发布 CLI 路径拒绝规则、密钥检查和安装顺序。

生产公开接口同样不接收密钥路径：主控使用 new tcs(host, port)，被控使用 new tcsd()。首次信任仍需通过 CLI 核对；改名后的程序默认主控模式，不存在 -i 密钥目录入口。临时路径重载只在测试工程的 TCS_TESTING 条件编译中存在，生产工程拒绝该编译符号。

旧 mTLS 程序和脚本已保留为 legacy 目录下的不可执行文本，不参与编译或打包。根目录旧安装/证书脚本只提示迁移，不再生成证书。服务安装脚本仍可配置服务及防火墙，但须管理员操作，且预先准备 LocalSystem 自身固定 .ssh 中的身份和授权；不复制或生成密钥，不把安装目录当作密钥目录。服务端 SCM 实际安装不属于普通回归测试。
