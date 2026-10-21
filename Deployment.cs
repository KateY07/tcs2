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
