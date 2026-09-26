using System.Net;
using System.Text;
using System.Text.Json;
using Tcs;

try
{
    await RunAsync(args);
}
catch (Exception exception)
{
    Console.Error.WriteLine(Deployment.FailureHint(exception));
    Console.Error.WriteLine($"tcs: operation failed: {exception}");
    Environment.ExitCode = 1;
}

static void PrintHelp(bool daemon)
{
    Console.WriteLine(daemon ? """
TCS 被控端：tcsd [options]

配对导入：
  tcsd pairing import <file.tcs-pair>
  可选：--trust-fingerprint <SHA256:...>（已通过可信渠道核对的主控指纹）

选项：
  -h, --help                    显示帮助
  --port <1-65535>              TCP 监听端口（默认：10122）
  --python <path>               Python 解释器路径（默认：PATH 中的 python）

示例：
  tcsd
  tcsd --port 10122

固定位置：%USERPROFILE%\.ssh\tcs_host_key、.ssh\authorized_keys。
本机公钥从私钥推导，同名 .pub 不读取、不检查、不修改。
数据固定为 %LOCALAPPDATA%\TCS\data，不允许指定其他目录。
安装前必须由用户生成密钥；导入及启动均不会自动生成密钥。保持窗口运行。
""" : """
TCS 主控端：tcs [options]

配对导出：
  tcs pairing export --output <file.tcs-pair>

选项：
  -h, --help                 显示帮助
  --host <name-or-address>   被控端地址（默认：127.0.0.1）
  --port <1-65535>           TCP 端口（默认：10122）
  --trust-fingerprint <fp>   已核对的 SHA256:... 指纹，用于非交互首次连接
  --operation <name>         操作：health、exec 或 upload（默认：health）
  --script <python>          exec 操作使用的 Python 源码
  --script-base64 <base64>   exec 操作使用的 UTF-8 Python 源码（Base64）
  --file <path>              upload 操作要上传的文件

示例：
  tcs --host server --operation health
  tcs --host server --operation exec --script "print('hello')"
  tcs --host server --operation upload --file .\report.txt

未固定公钥时会要求核对被控端指纹并确认，随后自动保存。已有身份变化时拒绝连接。
固定位置：%USERPROFILE%\.ssh\id_ed25519、.ssh\tcs_known_hosts。
本机公钥从私钥推导，同名 id_ed25519.pub 不读取、不检查、不修改。
兼容旧 .ssh\tcs_host_key.pub，生效时明确提示；所有密钥路径均不可指定。
远程 exec 在被控端运行 Python。
""");
}

static async Task RunAsync(string[] args)
{
var executableName = Path.GetFileNameWithoutExtension(Environment.ProcessPath);
if (args.Any(argument => argument is "--help" or "-h"))
{
    PrintHelp(string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase) || args.Contains("--tcsd"));
    return;
}

var daemonMode = args.FirstOrDefault() == "--tcsd" || string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase);
if (args.FirstOrDefault() == "--check-install")
{
    if (args.Length != 2) throw new ArgumentException("用法：--check-install controller|server");
    Deployment.CheckInstall(args[1]);
    return;
}
var removed = args.FirstOrDefault(argument => argument.Split('=')[0] is "--data" or "--client-key" or "--host-key" or "--authorized-keys" or "--server-key" or "--known-hosts" or "--generate-host-key" or "--verify-install");
if (removed is not null) throw new ArgumentException($"不再支持 {removed}：密钥须由用户提前生成，密钥和数据均使用固定路径。请运行 --help。");
var pairingArgs = args.FirstOrDefault() is "--tcsd" or "--tcs-client" ? args[1..] : args;
if (pairingArgs.FirstOrDefault() == "pairing")
{
    var export = !daemonMode && pairingArgs.ElementAtOrDefault(1) == "export";
    var import = daemonMode && pairingArgs.ElementAtOrDefault(1) == "import";
    if (!export && !import) throw new ArgumentException("用法：tcs pairing export --output <file>；tcsd pairing import <file>");
    var start = import ? 3 : 2;
    if (import && (pairingArgs.Length < 3 || pairingArgs[2].StartsWith('-'))) throw new ArgumentException("缺少要导入的配对文件。");
    Dictionary<string, string> options = new(StringComparer.Ordinal);
    for (var i = start; i < pairingArgs.Length; i += 2)
    {
        var option = pairingArgs[i];
        var allowed = export ? option is "--output" : option is "--trust-fingerprint";
        if (!allowed || i + 1 >= pairingArgs.Length || pairingArgs[i + 1].StartsWith("--") || !options.TryAdd(option, pairingArgs[i + 1]))
            throw new ArgumentException($"未知、重复或缺少值的配对参数：{option}");
    }
    if (export)
    {
        if (!options.TryGetValue("--output", out var output)) throw new ArgumentException("缺少 --output <file.tcs-pair>。");
        Pairing.Export(output);
    }
    else await Pairing.ImportAsync(pairingArgs[2], options.GetValueOrDefault("--trust-fingerprint"));
    return;
}

for (var i = args.FirstOrDefault() is "--tcsd" or "--tcs-client" ? 1 : 0; i < args.Length; i++)
{
    var option = args[i];
    if (daemonMode && option == "--service") continue;
    var allowed = daemonMode ? option is "--port" or "--python" or "--service-name" :
        option is "--host" or "--port" or "--trust-fingerprint" or "--operation" or "--script" or "--script-base64" or "--file";
    if (!allowed || i + 1 >= args.Length || args[i + 1].StartsWith("--") || Array.LastIndexOf(args, option) != i)
        throw new ArgumentException($"未知、重复或缺少值的参数：{option}");
    i++;
}

if (args.FirstOrDefault() == "--tcsd" || string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase))
{
    string Option(string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0) return fallback;
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--") || Array.LastIndexOf(args, name) != index)
            throw new ArgumentException($"参数重复或缺少值：{name}");
        return args[index + 1];
    }

    var python = Option("--python", "");
    Deployment.ValidatePair(Deployment.HostKey);
    if (python.Length > 0) Environment.SetEnvironmentVariable("TCS_PYTHON_EXE", python);
    if (args.Contains("--service"))
    {
        await DaemonService.RunAsync(Option("--service-name", "tcsd"), int.Parse(Option("--port", "10122")));
        return;
    }
    var daemon = new tcsd();
    await daemon.RunAsync(IPAddress.Any, int.Parse(Option("--port", "10122")));
    return;
}

if (!daemonMode)
{
    string Option(string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0) return fallback;
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--") || Array.LastIndexOf(args, name) != index)
            throw new ArgumentException($"参数重复或缺少值：{name}");
        return args[index + 1];
    }

    var operation = Option("--operation", "health");
    if (operation is not ("health" or "exec" or "upload")) throw new ArgumentException($"unknown client operation: {operation}");
    if (operation == "upload" && Option("--file", "").Length == 0) throw new ArgumentException("--file is required");
    var host = Option("--host", "127.0.0.1");
    var clientPort = int.Parse(Option("--port", "10122"));
    if (clientPort is < 1 or > 65535) throw new ArgumentException("--port 必须在 1 到 65535 之间。");
    var identity = Deployment.ClientKey;
    Deployment.ValidatePair(identity);
    await HostTrust.ResolveAsync(host, clientPort, args.Contains("--trust-fingerprint") ? Option("--trust-fingerprint", "") : null);
    var client = new tcs(host, clientPort);
    if (operation == "health")
    {
        Console.WriteLine((await client.HealthAsync()).GetRawText());
    }
    else if (operation == "exec")
    {
        var encodedScript = Option("--script-base64", "");
        var script = encodedScript.Length == 0 ? Option("--script", "print('ok')") : Encoding.UTF8.GetString(Convert.FromBase64String(encodedScript));
        Console.WriteLine((await client.ExecAsync(script)).GetRawText());
    }
    else if (operation == "upload")
    {
        var path = Option("--file", "");
        if (path.Length == 0)
        {
            throw new ArgumentException("--file is required");
        }
        Console.WriteLine((await client.UploadAsync(Path.GetFileName(path), await File.ReadAllBytesAsync(path))).GetRawText());
    }
    else
    {
        throw new ArgumentException($"unknown client operation: {operation}");
    }
    return;
}

throw new InvalidOperationException("无法识别 TCS 运行角色。");
}
