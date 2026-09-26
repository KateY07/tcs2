// tcs: a small mTLS-authenticated HTTP ops endpoint.
//
// Usage:
//   tcs.exe -i <keydir> -p <port>
//
// <keydir> must contain:
//   server.crt              PEM server certificate (presented to clients)
//   server.key              PEM server private key
//   authorized-clients.json JSON array of SHA-256 client-certificate
//                           thumbprints (hex, case-insensitive) that are
//                           allowed to connect -- this is the trust model,
//                           equivalent to SSH's authorized_keys: a client
//                           is trusted because its exact certificate is
//                           pinned here, not because some CA signed it.
//
// Endpoints (all require a client certificate whose SHA-256 thumbprint is
// in authorized-clients.json; TLS is mutual -- see BuildServerCertificate /
// ValidateClientCertificate below):
//   GET  /v1/health                     -> { "status": "ok" }
//   POST /v1/exec   { "script": "...",  -> runs the given Python source
//                     "timeoutSeconds": -    through `python <tempfile>`
//                       30 }                 (argv, never a shell string)
//                                            and returns stdout/stderr/exit
//   POST /v1/upload (multipart/form-data,   -> saves each uploaded file
//                    one or more files)         under ./uploads and
//                                                returns the saved names
//
// Every request is written to tcs-audit.log (JSON lines) next to the
// executable: timestamp, client certificate thumbprint, endpoint, and for
// /v1/exec the full script text and result. Nothing is hidden from that
// log on purpose -- the point of an ops channel is that what happened
// through it is fully reconstructable afterwards.

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Tcs;

try
{
    await RunAsync(args);
}
catch (Exception exception)
{
    Console.Error.WriteLine($"tcs: operation failed: {exception}");
    Environment.ExitCode = 1;
}

static void PrintHelp(bool daemon)
{
    Console.WriteLine(daemon ? """
TCS 被控端：tcsd [options]

配对导入：
  tcsd pairing import <file.tcs-pair>
  可选：--authorized-keys <path>、--host-key <path>
        --trust-fingerprint <SHA256:...>（已通过可信渠道核对的主控指纹）

选项：
  -h, --help                    显示帮助
  --port <1-65535>              TCP 监听端口（默认：10122）
  --authorized-keys <path>      主控端公钥列表（默认：~/.ssh/authorized_keys）
  --host-key <path>             被控端 OpenSSH 私钥（默认：~/.ssh/tcs_host_key）
  --data <directory>            上传文件及审计数据目录（默认：程序目录）
  --python <path>               Python 解释器路径（默认：PATH 中的 python）

示例：
  tcsd --data "$env:LOCALAPPDATA\TCS\data"
  tcsd --port 10122 --authorized-keys "$env:USERPROFILE\.ssh\authorized_keys" `
       --host-key "$env:USERPROFILE\.ssh\tcs_host_key" --data .\data

保持此进程运行以接受连接。pairing import 会调用 ssh-keygen 创建缺失的主机密钥，
经确认后添加主控公钥。普通启动不会自动创建密钥或授权文件。
""" : """
TCS 主控端：tcs [options]

配对导出：
  tcs pairing export --output <file.tcs-pair> [--client-key <private-key>]

选项：
  -h, --help                 显示帮助
  --host <name-or-address>   被控端地址（默认：127.0.0.1）
  --port <1-65535>           TCP 端口（默认：10122）
  --client-key <path>        主控端 OpenSSH 私钥（默认：~/.ssh/id_ed25519）
  --server-key <path>        显式指定被控端固定公钥，严格校验
  --known-hosts <directory>  按地址和端口保存公钥（默认：~/.ssh/tcs_known_hosts）
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
--server-key 显式指定时保持严格校验；默认兼容旧 ~/.ssh/tcs_host_key.pub。
远程 exec 在被控端运行 Python。
""");
}

static async Task RunAsync(string[] args)
{
var sshDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
string SshPath(string fileName) => Path.Combine(sshDirectory, fileName);
var executableName = Path.GetFileNameWithoutExtension(Environment.ProcessPath);
if (args.Any(argument => argument is "--help" or "-h"))
{
    PrintHelp(string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase) || args.Contains("--tcsd"));
    return;
}

var daemonMode = args.FirstOrDefault() == "--tcsd" || string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase);
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
        var allowed = export ? option is "--output" or "--client-key" : option is "--authorized-keys" or "--host-key" or "--trust-fingerprint";
        if (!allowed || i + 1 >= pairingArgs.Length || pairingArgs[i + 1].StartsWith("--") || !options.TryAdd(option, pairingArgs[i + 1]))
            throw new ArgumentException($"未知、重复或缺少值的配对参数：{option}");
    }
    if (export)
    {
        if (!options.TryGetValue("--output", out var output)) throw new ArgumentException("缺少 --output <file.tcs-pair>。");
        Pairing.Export(options.GetValueOrDefault("--client-key", SshPath("id_ed25519")), output);
    }
    else await Pairing.ImportAsync(pairingArgs[2], options.GetValueOrDefault("--authorized-keys", SshPath("authorized_keys")),
        options.GetValueOrDefault("--host-key", SshPath("tcs_host_key")), options.GetValueOrDefault("--trust-fingerprint"));
    return;
}

if (args.FirstOrDefault() == "--generate-host-key")
{
    if (args.Length != 2) throw new ArgumentException("Usage: --generate-host-key <path>");
    HostKeys.CreateOrExport(args[1]);
    return;
}

if (args.FirstOrDefault() == "--verify-install")
{
    if (args.Length != 5) throw new ArgumentException("Usage: --verify-install <port> <client-key> <server-key.pub> <data>");
    await InstallVerification.RunAsync(int.Parse(args[1]), args[2], args[3], args[4]);
    return;
}

if (args.FirstOrDefault() == "--tcsd" || string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase))
{
    string Option(string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
    }

    var python = Option("--python", "");
    if (python.Length > 0) Environment.SetEnvironmentVariable("TCS_PYTHON_EXE", python);
    if (args.Contains("--service"))
    {
        await DaemonService.RunAsync(Option("--service-name", "tcsd"),
            Option("--authorized-keys", SshPath("authorized_keys")),
            Option("--host-key", SshPath("tcs_host_key")),
            Option("--data", AppContext.BaseDirectory), int.Parse(Option("--port", "10122")));
        return;
    }
    var daemon = new tcsd(
        Option("--authorized-keys", SshPath("authorized_keys")),
        Option("--host-key", SshPath("tcs_host_key")),
        Option("--data", AppContext.BaseDirectory));
    await daemon.RunAsync(IPAddress.Any, int.Parse(Option("--port", "10122")));
    return;
}

if (args.FirstOrDefault() == "--tcs-client" || string.Equals(executableName, "tcs", StringComparison.OrdinalIgnoreCase))
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
    var identity = Option("--client-key", SshPath("id_ed25519"));
    var pinned = args.Contains("--server-key") ? Option("--server-key", "") :
        await HostTrust.ResolveAsync(host, clientPort, identity, Option("--known-hosts", SshPath("tcs_known_hosts")),
            args.Contains("--known-hosts") ? null : SshPath("tcs_host_key.pub"), args.Contains("--trust-fingerprint") ? Option("--trust-fingerprint", "") : null);
    if (pinned.Length == 0) throw new ArgumentException("--server-key 缺少路径。");
    if (args.Contains("--server-key") && args.Contains("--trust-fingerprint") &&
        Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(pinned)) != Option("--trust-fingerprint", ""))
        throw new CryptographicException("指定公钥文件与 --trust-fingerprint 不一致。");
    var client = new tcs(host, clientPort, identity, pinned);
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

var (keyDir, port) = ParseArgs(args);

var serverCertificate = BuildServerCertificate(
    Path.Combine(keyDir, "server.crt"),
    Path.Combine(keyDir, "server.key"));

var authorizedThumbprints = LoadAuthorizedClients(
    Path.Combine(keyDir, "authorized-clients.json"));

var auditLogPath = Path.Combine(AppContext.BaseDirectory, "tcs-audit.log");
var auditLock = new object();

var uploadsDir = Path.Combine(AppContext.BaseDirectory, "uploads");
Directory.CreateDirectory(uploadsDir);

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    // Kestrel's default 30MB request body cap exists to protect a public
    // web server from casual abuse. That's the wrong default here: this is
    // a trusted, cert-pinned ops channel whose whole job is to move files
    // and run scripts, and the default silently aborts the TLS connection
    // (the client sees a raw EOF, not a clean error) on anything larger.
    // Uncapped matches the "no concurrency cap" design elsewhere -- the
    // upload endpoint streams straight to disk, so this trades disk space
    // for the cap, not memory.
    options.Limits.MaxRequestBodySize = null;

    // IPAddress.Any (0.0.0.0) is IPv4-only and would silently refuse every
    // IPv6 connection -- fe80::/10 link-local, fd00::/8 ULA, real IPv6 LAN
    // addresses, all of it -- which defeats the point of testing this
    // alongside ardcore's IPv6 path handling. ListenAnyIP binds a single
    // dual-stack socket on IPv6Any so both address families are accepted.
    options.ListenAnyIP(port, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.ServerCertificate = serverCertificate;
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            // The trust decision is entirely thumbprint pinning, so we
            // deliberately ignore the chain / SslPolicyErrors that a
            // self-signed client certificate would otherwise fail with.
            httpsOptions.ClientCertificateValidation = (certificate, _, _) =>
                authorizedThumbprints.Contains(Sha256Thumbprint(certificate));
        });
    });
});

// ReadFormAsync() enforces its own separate 128MB multipart-body limit
// independent of Kestrel's MaxRequestBodySize above -- both have to be
// raised, or a large upload just fails at 128MB instead of 30MB.
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = long.MaxValue;
});

var app = builder.Build();

app.MapGet("/v1/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/v1/exec", async (HttpContext context, ExecRequest request) =>
{
    if (string.IsNullOrEmpty(request.Script))
    {
        return Results.BadRequest(new { error = "script must be a non-empty string" });
    }

    var thumbprint = ClientThumbprint(context);
    var timeout = TimeSpan.FromSeconds(request.TimeoutSeconds is > 0 ? request.TimeoutSeconds.Value : 30);
    var started = Stopwatch.StartNew();

    var scriptPath = Path.Combine(Path.GetTempPath(), "tcs", $"{Guid.NewGuid():N}.py");
    Directory.CreateDirectory(Path.GetDirectoryName(scriptPath)!);
    await File.WriteAllTextAsync(scriptPath, request.Script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    ExecResult result;
    try
    {
        result = await RunPythonAsync(scriptPath, timeout);
    }
    finally
    {
        TryDelete(scriptPath);
    }

    started.Stop();
    WriteAudit(JsonSerializer.Serialize(
        new LegacyExecAudit(DateTimeOffset.UtcNow, "/v1/exec", thumbprint, request.Script,
            started.ElapsedMilliseconds, result.ExitCode, result.TimedOut),
        TcsJsonContext.Default.LegacyExecAudit));

    return Results.Ok(result);
});

app.MapPost("/v1/upload", async (HttpContext context) =>
{
    var thumbprint = ClientThumbprint(context);
    if (!context.Request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "expected multipart/form-data" });
    }

    var form = await context.Request.ReadFormAsync();
    var saved = new List<string>();

    foreach (var file in form.Files)
    {
        // Strip any client-supplied directory components: only the file
        // name is trusted, and a fresh prefix avoids one upload silently
        // overwriting another (or an existing file) by name collision.
        var safeName = Path.GetFileName(file.FileName);
        if (string.IsNullOrWhiteSpace(safeName))
        {
            safeName = "upload.bin";
        }
        var storedName = $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}_{Guid.NewGuid():N}_{safeName}";
        var destinationPath = Path.Combine(uploadsDir, storedName);

        await using (var destination = File.Create(destinationPath))
        {
            await file.CopyToAsync(destination);
        }

        saved.Add(storedName);
    }

    WriteAudit(JsonSerializer.Serialize(
        new LegacyUploadAudit(DateTimeOffset.UtcNow, "/v1/upload", thumbprint, saved.ToArray()),
        TcsJsonContext.Default.LegacyUploadAudit));

    return Results.Ok(new { saved });
});

app.Run();

// ---- helpers ----------------------------------------------------------

static (string KeyDir, int Port) ParseArgs(string[] args)
{
    string? keyDir = null;
    int? port = null;

    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-i" when i + 1 < args.Length:
                keyDir = args[++i];
                break;
            case "-p" when i + 1 < args.Length:
                port = int.Parse(args[++i]);
                break;
        }
    }

    if (keyDir is null)
    {
        throw new ArgumentException("missing required -i <keydir> argument");
    }
    if (!Directory.Exists(keyDir))
    {
        throw new DirectoryNotFoundException($"key directory not found: {keyDir}");
    }

    return (keyDir, port ?? 10122);
}

static X509Certificate2 BuildServerCertificate(string certPath, string keyPath)
{
    if (!File.Exists(certPath))
    {
        throw new FileNotFoundException("server certificate not found", certPath);
    }
    if (!File.Exists(keyPath))
    {
        throw new FileNotFoundException("server private key not found", keyPath);
    }

    return X509Certificate2.CreateFromPemFile(certPath, keyPath);
}

static HashSet<string> LoadAuthorizedClients(string path)
{
    if (!File.Exists(path))
    {
        throw new FileNotFoundException(
            "authorized-clients.json not found next to server.crt/server.key", path);
    }

    var json = File.ReadAllText(path);
    var thumbprints = JsonSerializer.Deserialize(json, TcsJsonContext.Default.StringArray)
        ?? throw new InvalidDataException("authorized-clients.json must be a JSON array of strings");

    return thumbprints
        .Select(NormalizeThumbprint)
        .ToHashSet(StringComparer.Ordinal);
}

static string Sha256Thumbprint(X509Certificate2 certificate) =>
    NormalizeThumbprint(Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));

static string NormalizeThumbprint(string raw) =>
    raw.Replace(":", "").Replace(" ", "").Trim().ToUpperInvariant();

static string? ClientThumbprint(HttpContext context) =>
    context.Connection.ClientCertificate is { } cert ? Sha256Thumbprint(cert) : null;

static async Task<ExecResult> RunPythonAsync(string scriptPath, TimeSpan timeout)
{
    var pythonExe = Environment.GetEnvironmentVariable("TCS_PYTHON_EXE") is { Length: > 0 } configured
        ? configured
        : "python";

    var startInfo = new ProcessStartInfo
    {
        FileName = pythonExe,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    // Passed as an argv entry, never interpolated into a shell command
    // line: this is what sidesteps Windows/PowerShell quoting and
    // console-codepage encoding problems entirely.
    startInfo.ArgumentList.Add(scriptPath);

    using var process = new Process { StartInfo = startInfo };
    process.Start();

    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();

    using var cts = new CancellationTokenSource(timeout);
    var timedOut = false;
    try
    {
        await process.WaitForExitAsync(cts.Token);
    }
    catch (OperationCanceledException)
    {
        timedOut = true;
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception exception)
        {
            // best effort: process may have exited between the timeout
            // firing and Kill() being called
            Console.Error.WriteLine($"tcs: failed to kill timed-out Python process: {exception}");
        }
    }

    var stdout = await stdoutTask;
    var stderr = await stderrTask;

    return new ExecResult(
        ExitCode: timedOut ? null : process.ExitCode,
        Stdout: stdout,
        Stderr: stderr,
        TimedOut: timedOut);
}

static void TryDelete(string path)
{
    try
    {
        File.Delete(path);
    }
    catch (Exception exception)
    {
        // best effort cleanup only
        Console.Error.WriteLine($"tcs: failed to delete temporary script '{path}': {exception}");
    }
}

void WriteAudit(string line)
{
    lock (auditLock)
    {
        File.AppendAllText(auditLogPath, line + Environment.NewLine);
    }
}
}
