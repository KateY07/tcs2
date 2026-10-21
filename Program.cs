using System.Net;
using System.Text;
using System.Text.Json;
using Tcs;

var asDaemon = args.FirstOrDefault() == "--tcsd" || string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "tcsd", StringComparison.OrdinalIgnoreCase);
try
{
    await RunAsync(args);
}
catch (Exception exception)
{
    // Daemon operators get the full detail; the controller prints one message line (stack trace only with --verbose).
    Console.Error.WriteLine(CliOutput.FormatFailure(exception, asDaemon || args.Contains("--verbose")));
    if (exception is ArgumentException) Console.Error.WriteLine(asDaemon ? CliOutput.DaemonUsage : CliOutput.ClientUsage);
    Environment.ExitCode = asDaemon ? 1 : CliOutput.Failure;
}

static void PrintHelp(bool daemon)
{
    Console.WriteLine(daemon ? """
TCS controlled PC: tcsd [options]

PAIRING (first time, one minute, no files)
  tcsd pair                        start tcsd with a one-minute pairing window and show a 6-digit code
  (in a running tcsd press P)      open the window without restarting
  Then run on the controller:      tcs pair <this-computer> <code>
  Limits: 60 seconds, 3 attempts per window, single use; repeated failures from one address are blocked for 10 minutes.

PAIRING BY FILE (offline alternative)
  tcsd pairing import <file.tcs-pair>
  Optional: --trust-fingerprint <SHA256:...> (controller fingerprint verified through a trusted channel)
  A running tcsd loads the new authorization automatically; no restart is needed.

AUDIT
  tcsd audit [--tail N]            show the last N audit events (default 20)
  The log is data\tcs-audit.log (JSON lines): connections, denied attempts, pairing windows and attempts,
  exec/upload with the controller fingerprint, source address and a SHA-256 of the script. Rotated at 5 MB.

OPTIONS
  -h, --help                       show this help
  --port <1-65535>                 TCP listen port (default: 10122)
  --python <path>                  Python interpreter (default: python from PATH)

EXAMPLES
  tcsd
  tcsd pair
  tcsd --port 10122

Fixed locations: %USERPROFILE%\.ssh\tcs_host_key and .ssh\authorized_keys.
The public key is derived from the private key; a same-named .pub is not read, checked or modified.
Data lives in %LOCALAPPDATA%\TCS\data; no other folder can be chosen.
Keys must be created by you before installing; nothing here generates keys. Keep the window running.
""" : """
TCS controller: tcs <host> [health|exec|upload] [options]
Legacy form: tcs [options]

PAIRING (first time)
  tcs pair <host> <code> [--port N] [--json]   code shown by "tcsd pair" on the controlled PC
  tcs pairing export --output <file.tcs-pair>  offline alternative: export this controller's public key

OPTIONS
  -h, --help                 show this help
  --host <name-or-address>   controlled PC (default: 127.0.0.1)
  --port <1-65535>           TCP port (default: 10122)
  --trust-fingerprint <fp>   verified SHA256:... fingerprint for a non-interactive first connection
  --operation <name>         health, exec or upload (default: health)
  --script <python>          Python source for exec
  --script-base64 <base64>   UTF-8 Python source for exec (Base64)
  --file <path>              local UTF-8 Python file for exec, or the file to upload
  --max-output <N>           characters kept per output stream of exec (default: 16000, head and tail; 0 = unlimited)
  --json                     print the full JSON (default: remote stdout/stderr only)
  --meta                     always add one line with timing and sizes after exec
  --verbose                  show trust checks and stack traces

OUTPUT AND EXIT CODES (exec)
  stdout/stderr are the remote output; the exit code is the remote exit code (timeout 124, above 253 becomes 254).
  Only when something is abnormal one line "tcs: ..." is added to stderr.
  tcs's own errors (connection, identity, arguments, rejected authorization) exit 255.
  tcs pair exit codes: 0 paired, 10 not pairing, 11 bad code, 12 locked, 13 rate limited, 14 busy, 15 expired,
  16 protocol error, 255 other.

EXAMPLES
  tcs pair office-pc 481-937
  tcs office-pc health
  tcs office-pc exec "print('hello')"
  tcs office-pc exec --file "test.py"
  tcs office-pc upload .\demo.txt

First connection: the host fingerprint is shown and must be confirmed; it is then saved. A changed identity is refused.
Fixed locations: %USERPROFILE%\.ssh\id_ed25519 and .ssh\tcs_known_hosts.
The public key is derived from the private key; a same-named id_ed25519.pub is not read, checked or modified.
The old .ssh\tcs_host_key.pub is honoured with a warning. No key path can be set. exec runs Python on the controlled PC.
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
    if (args.Length != 2) throw new ArgumentException("Usage: --check-install controller|server");
    Deployment.CheckInstall(args[1]);
    return;
}
var removed = args.FirstOrDefault(argument => argument.Split('=')[0] is "--data" or "--client-key" or "--host-key" or "--authorized-keys" or "--server-key" or "--known-hosts" or "--generate-host-key" or "--verify-install");
if (removed is not null) throw new ArgumentException($"{removed} is no longer supported: keys must be created beforehand, and key and data paths are fixed. Run --help.");
var pairingArgs = args.FirstOrDefault() is "--tcsd" or "--tcs-client" ? args[1..] : args;
if (pairingArgs.FirstOrDefault() == "pairing")
{
    var export = !daemonMode && pairingArgs.ElementAtOrDefault(1) == "export";
    var import = daemonMode && pairingArgs.ElementAtOrDefault(1) == "import";
    if (!export && !import) throw new ArgumentException("Usage: tcs pairing export --output <file>; tcsd pairing import <file>");
    var start = import ? 3 : 2;
    if (import && (pairingArgs.Length < 3 || pairingArgs[2].StartsWith('-'))) throw new ArgumentException("Missing pairing file to import.");
    Dictionary<string, string> options = new(StringComparer.Ordinal);
    for (var i = start; i < pairingArgs.Length; i += 2)
    {
        var option = pairingArgs[i];
        var allowed = export ? option is "--output" : option is "--trust-fingerprint";
        if (!allowed || i + 1 >= pairingArgs.Length || pairingArgs[i + 1].StartsWith("--") || !options.TryAdd(option, pairingArgs[i + 1]))
            throw new ArgumentException($"Unknown, duplicate or valueless pairing option: {option}");
    }
    if (export)
    {
        if (!options.TryGetValue("--output", out var output)) throw new ArgumentException("Missing --output <file.tcs-pair>.");
        Pairing.Export(output);
    }
    else await Pairing.ImportAsync(pairingArgs[2], options.GetValueOrDefault("--trust-fingerprint"));
    return;
}

if (!daemonMode && pairingArgs.FirstOrDefault() == "pair")
{
    Environment.ExitCode = await PairCommand.RunAsync(pairingArgs[1..]);
    return;
}
if (daemonMode && pairingArgs.FirstOrDefault() == "audit")
{
    PairCommand.ShowAudit(pairingArgs[1..]);
    return;
}
var pairMode = daemonMode && pairingArgs.FirstOrDefault() == "pair";
if (pairMode)
{
    var pairAt = Array.IndexOf(args, "pair");
    args = args.Where((_, index) => index != pairAt).ToArray();
}

if (!daemonMode && args.Length == 0) throw new ArgumentException("The host address is missing.");
var clientOptions = daemonMode ? null : CliArguments.Parse(args);
for (var i = args.FirstOrDefault() is "--tcsd" or "--tcs-client" ? 1 : 0; daemonMode && i < args.Length; i++)
{
    var option = args[i];
    if (daemonMode && option == "--service") continue;
    var allowed = daemonMode ? option is "--port" or "--python" or "--service-name" :
        option is "--host" or "--port" or "--trust-fingerprint" or "--operation" or "--script" or "--script-base64" or "--file";
    if (!allowed || i + 1 >= args.Length || args[i + 1].StartsWith("--") || Array.LastIndexOf(args, option) != i)
        throw new ArgumentException($"Unknown, duplicate or valueless option: {option}");
    i++;
}

if (args.FirstOrDefault() == "--tcsd" || string.Equals(executableName, "tcsd", StringComparison.OrdinalIgnoreCase))
{
    string Option(string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0) return fallback;
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--") || Array.LastIndexOf(args, name) != index)
            throw new ArgumentException($"Duplicate option or missing value: {name}");
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
    var daemon = new tcsd { OpenPairingOnStart = pairMode };
    await daemon.RunAsync(IPAddress.Any, int.Parse(Option("--port", "10122")));
    return;
}

if (!daemonMode)
{
    string Option(string name, string fallback) => clientOptions!.GetValueOrDefault(name, fallback);

    var operation = Option("--operation", "health");
    if (operation is not ("health" or "exec" or "upload")) throw new ArgumentException($"unknown client operation: {operation}");
    if (operation == "upload" && Option("--file", "").Length == 0) throw new ArgumentException("--file is required");
    var host = Option("--host", "127.0.0.1");
    var clientPort = int.Parse(Option("--port", "10122"));
    if (clientPort is < 1 or > 65535) throw new ArgumentException("--port must be between 1 and 65535.");
    var script = operation == "exec" ? await CliArguments.ReadScriptAsync(clientOptions!) : null;
    var uploadBytes = operation == "upload" ? await File.ReadAllBytesAsync(Option("--file", "")) : null;
    int? maxOutput = clientOptions!.TryGetValue("--max-output", out var cap) ? int.Parse(cap) : null;
    Deployment.RequireKey(Deployment.ClientKey);
    HostTrust.Verbose = clientOptions.ContainsKey("--verbose");
    await HostTrust.ResolveAsync(host, clientPort, clientOptions.GetValueOrDefault("--trust-fingerprint"));
    var client = new tcs(host, clientPort);
    var started = System.Diagnostics.Stopwatch.StartNew();
    var result = operation switch
    {
        "health" => await client.HealthAsync(),
        "exec" => await client.ExecAsync(script!, maxOutput: maxOutput),
        _ => await client.UploadAsync(Path.GetFileName(Option("--file", "")), uploadBytes!),
    };
    Environment.ExitCode = CliOutput.Render(operation, result, clientOptions, Console.Out, Console.Error, started.Elapsed);
    return;
}

throw new InvalidOperationException("Cannot determine the TCS role.");
}
