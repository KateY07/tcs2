using System.Net.Sockets;

namespace Tcs;

internal static class Deployment
{
    internal static string SshDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
    internal static string ClientKey => Path.Combine(SshDirectory, "id_ed25519");
    internal static string HostKey => Path.Combine(SshDirectory, "tcs_host_key");
    internal static string AuthorizedKeys => Path.Combine(SshDirectory, "authorized_keys");
    internal static string KnownHosts => Path.Combine(SshDirectory, "tcs_known_hosts");
    internal static string Data => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TCS", "data");

    internal static string KeyInstructions(bool server)
    {
        var name = server ? "tcs_host_key" : "id_ed25519";
        return $$"""
若从未生成私钥，可在 PowerShell 运行以下脚本后重新安装。若已有身份，请先恢复原私钥到固定位置，不要重新生成。口令提示两次直接回车。
找不到 ssh-keygen 时，请安装 Windows 可选功能“OpenSSH 客户端”，不需要 OpenSSH 服务器。

$ErrorActionPreference = 'Stop'
$tcsKey = Join-Path $env:USERPROFILE '.ssh\{{name}}'
New-Item -ItemType Directory -Force (Split-Path $tcsKey) | Out-Null
if ((Test-Path -LiteralPath $tcsKey) -or (Test-Path -LiteralPath ($tcsKey + '.pub'))) {
    throw "密钥或公钥已经存在，请检查并恢复原私钥，不要覆盖：$tcsKey"
} else {
    ssh-keygen -t ed25519 -f $tcsKey
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen 生成失败' }
}
""";
    }

    internal static byte[] ValidatePair(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"缺少私钥：{path}。请恢复已有身份或由用户提前生成；不要求 .pub 文件，不会自动生成密钥。");
        var key = TcsCrypto.ReadPrivateKey(path);
        var blob = TcsCrypto.PublicBlob(key);
        Pairing.PublicLine(blob);
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        if (!TcsCrypto.Verify(Org.BouncyCastle.Crypto.Utilities.OpenSshPublicKeyUtilities.ParsePublicKey(blob), challenge, TcsCrypto.Sign(key, challenge)))
            throw new InvalidDataException("密钥签名自检失败。");
        return blob;
    }

    internal static void CheckInstall(string role)
    {
        if (role is not ("controller" or "server")) throw new ArgumentException("安装角色必须为 controller 或 server。");
        var server = role == "server";
        var path = server ? HostKey : ClientKey;
        byte[] blob;
        try { blob = ValidatePair(path); }
        catch (Exception)
        {
            Console.Error.WriteLine($"安装前检查失败：{path}\n需要可读取、无口令的 OpenSSH 私钥；不要求 .pub 文件。不会修改密钥或继续安装。\n{KeyInstructions(server)}");
            throw;
        }
        Console.WriteLine($"安装前检查通过：{path}\n公钥指纹（从私钥推导）：{Pairing.Fingerprint(blob)}");
    }

    internal static string FailureHint(Exception error) => error switch
    {
        SocketException socket when socket.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData => "地址解析失败：请核对被控端名称，或使用其可达 IP 地址。",
        SocketException socket when socket.SocketErrorCode == SocketError.ConnectionRefused => "TCP 连接被拒绝：请检查被控端 tcsd 是否运行、端口是否一致；本次未完成认证。",
        SocketException => "TCP 网络连接失败：请检查地址、路由和该端口的防火墙规则。Ping/RDP 成功不代表此端口可达。",
        EndOfStreamException => "对端在握手或传输完成前关闭连接：请检查被控端日志和主控公钥授权；不能仅凭断开判断为防火墙问题。",
        OperationCanceledException or TimeoutException => "连接或握手超时/取消：请检查被控端状态和网络。不要自动重试可能已经执行的远程指令。",
        FileNotFoundException => "缺少所需文件：密钥须提前放在固定路径；被控端缺少 authorized_keys 时先导入配对文件。",
        System.Security.Cryptography.CryptographicException => "身份或签名校验失败：连接已拒绝。请通过可信渠道核对双方身份，不要盲目删除信任记录。",
        ArgumentException => "参数错误：请运行 --help；密钥路径和数据目录固定，不接受路径覆盖参数。",
        _ => "操作未完成，请检查以下详细错误。"
    };
}
