using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Tcs;

internal static class HostTrust
{
    internal static bool Verbose;

#if !TCS_TESTING
    internal static string PinnedPath(string host, int port)
    {
        var endpoint = EndpointPath(host, port, Deployment.KnownHosts);
        if (File.Exists(endpoint)) return endpoint;
        if (File.Exists(Deployment.HostKey + ".pub")) return Deployment.HostKey + ".pub";
        throw new InvalidOperationException("This controlled PC is not trusted yet: connect once with tcs <host> and verify its fingerprint, or pair with tcs pair <host> <code>.");
    }
#endif

    // Pins the host key learned by pairing; the pairing code authenticated it, so there is no fingerprint to compare by eye.
#if TCS_TESTING
    internal static void PinPaired(string host, int port, string directory, byte[] blob)
#else
    internal static void PinPaired(string host, int port, byte[] blob)
#endif
    {
#if !TCS_TESTING
        var directory = Deployment.KnownHosts;
#endif
        var path = EndpointPath(host, port, directory);
        if (File.Exists(path))
        {
            if (!TcsCrypto.ReadPublicKeyBlob(path).SequenceEqual(blob))
                throw new CryptographicException("This host is already pinned to a different identity; pairing will not overwrite it. If the controlled PC was reinstalled, remove its saved trust record first.");
            return;
        }
        Deployment.EnsureSshDirectory(directory);
        Pairing.AtomicWrite(path, Pairing.PublicLine(blob) + "\n", false);
    }

    static string EndpointPath(string host, int port, string directory)
    {
        var normalized = IPAddress.TryParse(host, out var address) ? address.ToString() : host.ToLowerInvariant().TrimEnd('.');
        var name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{normalized}:{port}"))).ToLowerInvariant() + ".pub";
        return Path.Combine(Path.GetFullPath(directory), name);
    }

#if TCS_TESTING
    internal static async Task<string> ResolveAsync(string host, int port, string identity, string directory, string? legacyKey, string? expected)
#else
    internal static async Task<string> ResolveAsync(string host, int port, string? expected)
#endif
    {
#if !TCS_TESTING
        var directory = Deployment.KnownHosts;
        var legacyKey = Deployment.HostKey + ".pub";
#endif
        var path = EndpointPath(host, port, directory);
        var existing = File.Exists(path) ? path : legacyKey is not null && File.Exists(legacyKey) ? legacyKey : null;
        if (existing is not null)
        {
            var savedFingerprint = Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(existing));
            if (existing != path)
                Console.Error.WriteLine($"Legacy pinned key in effect: {existing}\nPinned fingerprint: {savedFingerprint}\nTarget [{host}]:{port} has no record of its own, so the legacy key is checked strictly and no first-use confirmation is asked. If the target does not match the connection is refused; do not delete or overwrite this file blindly.");
            else if (Verbose) Console.Error.WriteLine($"Verifying the saved identity of the controlled PC: [{host}]:{port}\nTrust record: {existing}");
            if (expected is not null && Pairing.Fingerprint(TcsCrypto.ReadPublicKeyBlob(existing)) != expected)
                throw new CryptographicException("The provided fingerprint does not match the pinned key; the original identity is not overwritten.");
            return existing;
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Console.Error.WriteLine($"Probing the host identity of [{host}]:{port}; no commands or files are sent until you confirm.");
#if TCS_TESTING
        var blob = await global::tcs.InspectServerKeyAsync(host, port, identity, deadline.Token);
#else
        var blob = await global::tcs.InspectServerKeyAsync(host, port, deadline.Token);
#endif
        var fingerprint = Pairing.Fingerprint(blob);
        Console.Error.WriteLine($"First connection to controlled PC [{host}]:{port}\nHost fingerprint: {fingerprint}");
        Pairing.Confirm(fingerprint, expected);
        Deployment.EnsureSshDirectory(Path.GetDirectoryName(path)!);
        try { Pairing.AtomicWrite(path, Pairing.PublicLine(blob) + "\n", false); }
        catch (IOException) when (File.Exists(path))
        {
            if (!TcsCrypto.ReadPublicKeyBlob(path).SequenceEqual(blob))
                throw new CryptographicException("Another process already saved a different host key; refusing to overwrite.");
            Console.Error.WriteLine("Another connection already saved the same host key.");
        }
        Console.Error.WriteLine($"Pinned the host key: {path}\nReconnecting with the confirmed identity...");
        return path;
    }
}
