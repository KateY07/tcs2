using System.Net.Sockets;

namespace Tcs;

internal static class Deployment
{
    internal static string SshDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
    internal static string ClientKey => Path.Combine(SshDirectory, "id_ed25519");
    internal static string HostKey => Path.Combine(SshDirectory, "tcs_host_key");
    internal static string AuthorizedKeys => Path.Combine(SshDirectory, "authorized_keys");
    internal static string KnownHosts => Path.Combine(SshDirectory, "tcs_known_hosts");
    internal static string Data => Path.Combine(LocalData, "TCS", "data");

    // %LOCALAPPDATA% on Windows; $XDG_DATA_HOME or ~/.local/share on Unix (GetFolderPath returns "" there when the folder does not exist yet).
    static string LocalData
    {
        get
        {
            if (OperatingSystem.IsWindows()) return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } xdg && Path.IsPathRooted(xdg)) return xdg;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        }
    }

    // Creates ~/.ssh (mode 700 on Unix) if it does not exist yet.
    internal static void EnsureSshDirectory(string directory)
    {
        if (Directory.Exists(directory)) return;
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
        else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    internal static string KeyInstructions(bool server)
    {
        var name = server ? "tcs_host_key" : "id_ed25519";
        if (!OperatingSystem.IsWindows()) return $"""
If you have never created a private key, run this once, then install again. If you already have an identity, restore the original private key to the fixed location; do not regenerate it.

mkdir -p -m 700 ~/.ssh && test ! -e ~/.ssh/{name} && ssh-keygen -t ed25519 -N "" -f ~/.ssh/{name}
""";
        return $$"""
If you have never created a private key, run the script below in PowerShell, then install again. If you already have an identity, restore the original private key to the fixed location; do not regenerate it. Press Enter twice at the passphrase prompts.
If ssh-keygen is missing, install the Windows optional feature "OpenSSH Client" (the OpenSSH server is not needed).

$ErrorActionPreference = 'Stop'
$tcsKey = Join-Path $env:USERPROFILE '.ssh\{{name}}'
New-Item -ItemType Directory -Force (Split-Path $tcsKey) | Out-Null
if ((Test-Path -LiteralPath $tcsKey) -or (Test-Path -LiteralPath ($tcsKey + '.pub'))) {
    throw "A key or public key already exists. Check and restore the original private key; do not overwrite: $tcsKey"
} else {
    ssh-keygen -t ed25519 -f $tcsKey
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed' }
}
""";
    }

    internal static byte[] ValidatePair(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Private key not found: {path}. Restore the existing identity or create one beforehand; a .pub file is not required and keys are never generated automatically.");
        var key = TcsCrypto.ReadPrivateKey(path);
        var blob = TcsCrypto.PublicBlob(key);
        Pairing.PublicLine(blob);
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        if (!TcsCrypto.Verify(Org.BouncyCastle.Crypto.Utilities.OpenSshPublicKeyUtilities.ParsePublicKey(blob), challenge, TcsCrypto.Sign(key, challenge)))
            throw new InvalidDataException("Key signature self-test failed.");
        return blob;
    }

    internal static void CheckInstall(string role)
    {
        if (role is not ("controller" or "server")) throw new ArgumentException("The install role must be controller or server.");
        var server = role == "server";
        var path = server ? HostKey : ClientKey;
        byte[] blob;
        try { blob = ValidatePair(path); }
        catch (Exception)
        {
            Console.Error.WriteLine($"Pre-install check failed: {path}\nA readable OpenSSH private key without a passphrase is required (a .pub file is not). Nothing was changed and the install will not continue.\n{KeyInstructions(server)}");
            throw;
        }
        Console.WriteLine($"Pre-install check passed: {path}\nPublic key fingerprint (derived from the private key): {Pairing.Fingerprint(blob)}");
    }

    internal const string ServiceTaskName = "TCS controlled PC (tcsd)";

    // Registers (or removes) a per-user logon task that starts tcsd in the user's interactive session, where the
    // activity watermark can be shown. No administrator rights are needed for the current user's own logon task.
    // This is deliberately not a Windows service: a session-0 service has no desktop, so it could never show the
    // watermark and would refuse every command.
    internal static void ServiceTask(bool install, string[] options)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("install-service is Windows-only. On Linux use the systemd unit (see tcsd.service in the Linux package).");
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine this executable's path.");
        var port = "10122";
        for (var i = 0; i < options.Length; i += 2)
        {
            if (options[i] != "--port" || i + 1 >= options.Length) throw new ArgumentException("Usage: tcsd install-service [--port N] | tcsd uninstall-service");
            if (!int.TryParse(options[i + 1], out var p) || p is < 1 or > 65535) throw new ArgumentException("--port must be 1-65535.");
            port = options[i + 1];
        }
        if (install) RequireKey(HostKey);   // fail early if the host key is missing

        var schtasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
        var startInfo = new System.Diagnostics.ProcessStartInfo { FileName = schtasks, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        if (install)
        {
            foreach (var a in new[] { "/Create", "/TN", ServiceTaskName, "/SC", "ONLOGON", "/TR", $"\"{exe}\" --port {port}", "/RL", "LIMITED", "/IT", "/F" })
                startInfo.ArgumentList.Add(a);
        }
        else
        {
            foreach (var a in new[] { "/Delete", "/TN", ServiceTaskName, "/F" }) startInfo.ArgumentList.Add(a);
        }
        using var process = System.Diagnostics.Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start schtasks.exe.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"schtasks failed (exit {process.ExitCode}): {output.Trim()}");
        Console.WriteLine(install
            ? $"Registered the logon task \"{ServiceTaskName}\": tcsd will start at sign-in on TCP {port} and show the activity watermark.\nStart it now without signing out again: schtasks /Run /TN \"{ServiceTaskName}\"\nRemove it with: tcsd uninstall-service\nPairing is never opened by the task; run \"tcsd pair\" in a terminal to pair."
            : $"Removed the logon task \"{ServiceTaskName}\". A running tcsd is not stopped; close its window or sign out.");
    }

    // Cheap per-call check; the full sign/verify self-test stays in ValidatePair (install check, daemon start, pairing).
    internal static void RequireKey(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Private key not found: {path}. Restore the existing identity or create one beforehand; a .pub file is not required and keys are never generated automatically.");
    }

    internal static string? FailureHint(Exception error) => error switch
    {
        TcsRejectedException rejected => $"The controlled PC rejected this controller ({rejected.Name}): {rejected.Message}. If this controller was never paired, run tcsd pair on the controlled PC, then tcs pair <host> <code> here.",
        SocketException socket when socket.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData => "Name resolution failed: check the computer name or use a reachable IP address.",
        SocketException socket when socket.SocketErrorCode == SocketError.ConnectionRefused => "TCP connection refused: check that tcsd is running on the controlled PC and that both sides use the same port. Nothing was authenticated.",
        SocketException => "TCP connection failed: check the address, routing and the firewall rule for this port. A working ping or RDP does not mean this port is reachable.",
        EndOfStreamException => "The peer closed the connection during the handshake: check the tcsd log on the controlled PC. This does not by itself mean a firewall problem.",
        OperationCanceledException or TimeoutException => "The connection or handshake timed out or was cancelled: check the controlled PC and the network. Do not retry blindly: a remote command may already have run.",
        FileNotFoundException => "A required file is missing: keys must already exist in their fixed locations; if authorized_keys is missing on the controlled PC, pair first.",
        System.Security.Cryptography.CryptographicException => "Identity or signature verification failed and the connection was refused. Verify both identities through a trusted channel; do not delete trust records blindly.",
        ArgumentException => null,
        _ => null
    };
}
