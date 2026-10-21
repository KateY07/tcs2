using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Tcs;

// Pairing by one-time code.
//
// The controlled PC opens a short pairing window (default 60 s, 3 attempts, single use) and shows a 6-digit code. The
// controller proves it knows the code with SPAKE2 (RFC 9382 construction on P-256, SHA-256), so an eavesdropper or an
// active man in the middle gets one online guess per session and nothing to attack offline. After both sides have
// confirmed the same key, each sends its public key sealed under that key: the controlled PC authorizes the controller
// key immediately (no restart) and the controller pins the host key (no fingerprint to compare by eye).
//
// Note: this SPAKE2 is implemented here on top of BouncyCastle; it follows the RFC but has not been independently audited.
internal enum PairResult : ushort
{
    Paired = 0,
    AlreadyPaired = 1,
    NotPairing = 10,
    BadCode = 11,
    Locked = 12,
    RateLimited = 13,
    Busy = 14,
    Expired = 15,
    ProtocolError = 16,
    InternalError = 17,
}

internal sealed class PairException : Exception
{
    public PairResult Result { get; }
    public int AttemptsLeft { get; }
    public int RetryAfterSeconds { get; }

    public PairException(PairResult result, string message, int attemptsLeft = -1, int retryAfterSeconds = 0) : base(message)
    {
        Result = result;
        AttemptsLeft = attemptsLeft;
        RetryAfterSeconds = retryAfterSeconds;
    }

    public static string Name(PairResult result) => result switch
    {
        PairResult.Paired => "PAIRED",
        PairResult.AlreadyPaired => "ALREADY_PAIRED",
        PairResult.NotPairing => "NOT_PAIRING",
        PairResult.BadCode => "BAD_CODE",
        PairResult.Locked => "LOCKED",
        PairResult.RateLimited => "RATE_LIMITED",
        PairResult.Busy => "BUSY",
        PairResult.Expired => "EXPIRED",
        PairResult.ProtocolError => "PROTOCOL_ERROR",
        _ => "INTERNAL_ERROR"
    };

    // Process exit code of "tcs pair": 0 on success, 10..17 for the refusal reasons.
    public static int ExitCode(PairResult result) => result is PairResult.Paired or PairResult.AlreadyPaired ? 0 : (int)result;
}

internal static class Spake2
{
    static readonly X9ECParameters Curve = CustomNamedCurves.GetByName("secp256r1");
    // M and N are derived from fixed labels by hash-and-check, so nobody knows their discrete logarithms.
    static readonly ECPoint M = HashToPoint("TCS-PAIR/SPAKE2/M");
    static readonly ECPoint N = HashToPoint("TCS-PAIR/SPAKE2/N");

    static ECPoint HashToPoint(string label)
    {
        var prime = Curve.Curve.Field.Characteristic;
        for (var counter = 0; ; counter++)
        {
            var x = new BigInteger(1, SHA256.HashData(Encoding.UTF8.GetBytes(label + "/" + counter))).Mod(prime);
            var encoded = new byte[33];
            encoded[0] = 0x02;
            BigIntegers.AsUnsignedByteArray(x, encoded, 1, 32);
            try
            {
                var point = Curve.Curve.DecodePoint(encoded).Normalize();
                if (!point.IsInfinity && point.IsValid()) return point;
            }
            catch (ArgumentException) { }
        }
    }

    public static string NormalizeCode(string code)
    {
        var digits = new string(code.Where(char.IsAsciiDigit).ToArray());
        var separators = code.Count(c => c is '-' or ' ');
        if (digits.Length != 6 || digits.Length + separators != code.Length)
            throw new ArgumentException("The pairing code is six digits, for example 481-937.");
        return digits;
    }

    public static string FormatCode(string digits) => digits[..3] + "-" + digits[3..];

    static BigInteger Password(string digits)
    {
        var material = HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.ASCII.GetBytes(digits), 48, Encoding.ASCII.GetBytes("TCS-PAIR/SPAKE2/w"), Encoding.ASCII.GetBytes("w"));
        return new BigInteger(1, material).Mod(Curve.N);
    }

    static BigInteger RandomScalar()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);
        return new BigInteger(1, bytes).Mod(Curve.N.Subtract(BigInteger.One)).Add(BigInteger.One);
    }

    static ECPoint Decode(byte[] encoded)
    {
        if (encoded.Length != 65 || encoded[0] != 0x04) throw new PairException(PairResult.ProtocolError, "Malformed pairing message.");
        try
        {
            var point = Curve.Curve.DecodePoint(encoded).Normalize();
            if (point.IsInfinity || !point.IsValid()) throw new PairException(PairResult.ProtocolError, "Invalid pairing message.");
            return point;
        }
        catch (ArgumentException) { throw new PairException(PairResult.ProtocolError, "Invalid pairing message."); }
    }

    public sealed class Keys
    {
        public byte[] ConfirmClient = [], ConfirmServer = [], Seal = [], TranscriptHash = [];
    }

    // The party computing the message: client sends X = x*G + w*M, server sends Y = y*G + w*N.
    public sealed class Party
    {
        readonly BigInteger secret, w;
        readonly bool client;
        public byte[] Message { get; }

        public Party(string digits, bool isClient)
        {
            client = isClient;
            w = Password(digits);
            secret = RandomScalar();
            Message = Curve.G.Multiply(secret).Add((isClient ? M : N).Multiply(w)).Normalize().GetEncoded(false);
        }

        public Keys Finish(byte[] peerMessage)
        {
            var peer = Decode(peerMessage);
            var shared = peer.Subtract((client ? N : M).Multiply(w)).Multiply(secret).Normalize();
            if (shared.IsInfinity) throw new PairException(PairResult.ProtocolError, "Invalid pairing exchange.");
            var x = client ? Message : peerMessage;
            var y = client ? peerMessage : Message;
            using var transcript = new MemoryStream();
            foreach (var part in new[] { Encoding.ASCII.GetBytes("TCS-PAIR/1"), Encoding.ASCII.GetBytes("tcs-controller"), Encoding.ASCII.GetBytes("tcsd"), x, y, shared.GetEncoded(false), BigIntegers.AsUnsignedByteArray(32, w) })
            {
                transcript.Write(BitConverter.GetBytes(part.Length));
                transcript.Write(part);
            }
            var hash = SHA256.HashData(transcript.ToArray());
            var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, hash, 96, null, Encoding.ASCII.GetBytes("TCS-PAIR/keys"));
            return new Keys { ConfirmClient = okm[..32], ConfirmServer = okm[32..64], Seal = okm[64..], TranscriptHash = hash };
        }
    }

    public static byte[] Confirm(byte[] key, string role, byte[] transcriptHash) =>
        HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(role).Concat(transcriptHash).ToArray());

    public static byte[] Seal(Keys keys, int counter, byte[] plaintext)
    {
        var nonce = new byte[12];
        nonce[11] = (byte)counter;
        var output = new byte[plaintext.Length + 16];
        using var cipher = new ChaCha20Poly1305(keys.Seal);
        cipher.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), keys.TranscriptHash);
        return output;
    }

    public static byte[] Open(Keys keys, int counter, byte[] sealedData)
    {
        if (sealedData.Length < 16) throw new PairException(PairResult.ProtocolError, "Malformed sealed key.");
        var nonce = new byte[12];
        nonce[11] = (byte)counter;
        var plaintext = new byte[sealedData.Length - 16];
        using var cipher = new ChaCha20Poly1305(keys.Seal);
        try { cipher.Decrypt(nonce, sealedData.AsSpan(0, plaintext.Length), sealedData.AsSpan(plaintext.Length), plaintext, keys.TranscriptHash); }
        catch (CryptographicException) { throw new PairException(PairResult.BadCode, "The pairing exchange could not be verified."); }
        return plaintext;
    }
}

// ---------------------------------------------------------------- wire helpers
internal static class PairWire
{
    public const byte HelloType = 0x20;   // after the usual "TCS1" + type + version + cipher prefix
    const int MaxText = 512, MaxSealed = 4096;

    public static byte[] Prefix() => [(byte)'T', (byte)'C', (byte)'S', (byte)'1', HelloType, 0, 1, 0, 0];

    public static async Task WriteErrorAsync(Stream stream, PairResult result, string text, int attemptsLeft, int retryAfter, CancellationToken ct)
    {
        var message = Encoding.UTF8.GetBytes(text.Length > MaxText ? text[..MaxText] : text);
        using var output = new MemoryStream();
        output.WriteByte(1);
        output.Write(BitConverter.GetBytes((ushort)result));
        output.Write(BitConverter.GetBytes((ushort)Math.Clamp(retryAfter, 0, ushort.MaxValue)));
        output.WriteByte((byte)(attemptsLeft < 0 ? 255 : Math.Min(attemptsLeft, 254)));
        output.Write(BitConverter.GetBytes((ushort)message.Length));
        output.Write(message);
        await TcsWire.WriteAllAsync(stream, output.ToArray(), ct);
    }

    // Reads a status byte; throws the server's refusal as PairException.
    public static async Task ExpectOkAsync(Stream stream, CancellationToken ct)
    {
        var status = new byte[1];
        await TcsWire.ReadExactAsync(stream, status, ct);
        if (status[0] == 0) return;
        if (status[0] != 1) throw new PairException(PairResult.ProtocolError, "Unexpected reply from the controlled PC.");
        var head = new byte[7];
        await TcsWire.ReadExactAsync(stream, head, ct);
        var result = (PairResult)BitConverter.ToUInt16(head, 0);
        var retry = BitConverter.ToUInt16(head, 2);
        int attempts = head[4] == 255 ? -1 : head[4];
        int length = BitConverter.ToUInt16(head, 5);
        if (length > MaxText) throw new PairException(PairResult.ProtocolError, "Oversized reply from the controlled PC.");
        var text = new byte[length];
        await TcsWire.ReadExactAsync(stream, text, ct);
        throw new PairException(Enum.IsDefined(result) ? result : PairResult.ProtocolError, Encoding.UTF8.GetString(text), attempts, retry);
    }

    public static async Task WriteSealedAsync(Stream stream, byte[] data, CancellationToken ct)
    {
        using var output = new MemoryStream();
        output.Write(BitConverter.GetBytes((uint)data.Length));
        output.Write(data);
        await TcsWire.WriteAllAsync(stream, output.ToArray(), ct);
    }

    public static async Task<byte[]> ReadSealedAsync(Stream stream, CancellationToken ct)
    {
        var length = new byte[4];
        await TcsWire.ReadExactAsync(stream, length, ct);
        var size = BitConverter.ToUInt32(length);
        if (size == 0 || size > MaxSealed) throw new PairException(PairResult.ProtocolError, "Invalid sealed key size.");
        var data = new byte[size];
        await TcsWire.ReadExactAsync(stream, data, ct);
        return data;
    }
}

// ---------------------------------------------------------------- controller side
internal static class PairClient
{
    // Returns the controlled PC's public key blob; throws PairException with an explicit result otherwise.
    public static async Task<(byte[] HostBlob, bool AlreadyPaired)> PairAsync(string host, int port, string code, byte[] clientBlob, CancellationToken ct)
    {
        var digits = Spake2.NormalizeCode(code);
        using var tcp = new TcpClient(AddressFamily.InterNetworkV6) { NoDelay = true };
        tcp.Client.DualMode = true;
        await tcp.ConnectAsync(host, port, ct);
        await using var stream = tcp.GetStream();

        var party = new Spake2.Party(digits, isClient: true);
        await TcsWire.WriteAllAsync(stream, PairWire.Prefix().Concat(party.Message).ToArray(), ct);

        await PairWire.ExpectOkAsync(stream, ct);
        var reply = new byte[65 + 32];
        await TcsWire.ReadExactAsync(stream, reply, ct);
        var keys = party.Finish(reply[..65]);
        if (!CryptographicOperations.FixedTimeEquals(reply.AsSpan(65), Spake2.Confirm(keys.ConfirmServer, "server", keys.TranscriptHash)))
            throw new PairException(PairResult.BadCode, "The pairing code is wrong (or the connection is not the PC that showed it).");

        using var second = new MemoryStream();
        second.Write(Spake2.Confirm(keys.ConfirmClient, "client", keys.TranscriptHash));
        var sealedKey = Spake2.Seal(keys, 1, clientBlob);
        second.Write(BitConverter.GetBytes((uint)sealedKey.Length));
        second.Write(sealedKey);
        await TcsWire.WriteAllAsync(stream, second.ToArray(), ct);

        await PairWire.ExpectOkAsync(stream, ct);
        var already = new byte[1];
        await TcsWire.ReadExactAsync(stream, already, ct);
        var hostBlob = Spake2.Open(keys, 2, await PairWire.ReadSealedAsync(stream, ct));
        Pairing.PublicLine(hostBlob);   // validates the key type
        return (hostBlob, already[0] == 1);
    }
}

// ---------------------------------------------------------------- controlled side
internal sealed class PairingServer
{
    public const int DefaultSeconds = 60, DefaultAttempts = 3;
    const int MinSecondsBetweenAttempts = 2, FailuresBeforeBlock = 3, BlockMinutes = 10, ProbesPerMinute = 10, StepTimeoutSeconds = 5;

    sealed class Window
    {
        public string Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
        public string Digits = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        public DateTimeOffset Expires;
        public int AttemptsLeft;
        public bool Busy;
        public Timer? Timer;
    }

    sealed class Peer
    {
        public int Failures;
        public DateTimeOffset BlockedUntil, LastAttempt;
        public DateTimeOffset ProbeWindowStart;
        public int Probes;
    }

    readonly byte[] hostBlob;
    readonly Func<byte[], bool> authorize;          // adds the controller key; returns true if it was already authorized
    readonly Action<string, string?, string, string?> audit;   // event, fingerprint, result, detail
    readonly Action<string> log;
    readonly int seconds, attempts;
    readonly object gate = new();
    readonly Dictionary<IPAddress, Peer> peers = [];
    Window? window;
    DateTimeOffset lastClosed;
    string lastCloseReason = "";

    public PairingServer(byte[] hostBlob, Func<byte[], bool> authorize, Action<string, string?, string, string?> audit, Action<string> log, int seconds = DefaultSeconds, int attempts = DefaultAttempts)
    {
        this.hostBlob = hostBlob;
        this.authorize = authorize;
        this.audit = audit;
        this.log = log;
        this.seconds = seconds;
        this.attempts = attempts;
    }

    public bool IsOpen { get { lock (gate) return window is { } w && w.Expires > DateTimeOffset.UtcNow && w.AttemptsLeft > 0; } }

    // Opens (or returns) the single pairing window. Only local actions call this: "tcsd pair" or the P key.
    public (string Code, DateTimeOffset Expires) Open(string? fixedDigits = null)
    {
        lock (gate)
        {
            if (window is { } current && current.Expires > DateTimeOffset.UtcNow && current.AttemptsLeft > 0)
                return (Spake2.FormatCode(current.Digits), current.Expires);
            var fresh = new Window { Expires = DateTimeOffset.UtcNow.AddSeconds(seconds), AttemptsLeft = attempts };
            if (fixedDigits is not null) fresh.Digits = fixedDigits;   // tests only
            fresh.Timer = new Timer(_ => Close(fresh, "expired"), null, TimeSpan.FromSeconds(seconds), Timeout.InfiniteTimeSpan);
            window = fresh;
            audit("pair-window-open", null, "OPEN", $"id={fresh.Id} seconds={seconds} attempts={attempts}");
            return (Spake2.FormatCode(fresh.Digits), fresh.Expires);
        }
    }

    void Close(Window target, string reason)
    {
        lock (gate)
        {
            if (window != target) return;
            target.Timer?.Dispose();
            window = null;
            lastClosed = DateTimeOffset.UtcNow;
            lastCloseReason = reason;
        }
        audit("pair-window-close", null, reason.ToUpperInvariant(), $"id={target.Id}");
        log($"Pairing window closed ({reason}).");
    }

    Peer PeerFor(IPAddress address, DateTimeOffset now)
    {
        if (peers.Count > 2048)
            foreach (var stale in peers.Where(p => p.Value.BlockedUntil < now && now - p.Value.LastAttempt > TimeSpan.FromMinutes(BlockMinutes)).Select(p => p.Key).ToList())
                peers.Remove(stale);
        if (!peers.TryGetValue(address, out var peer)) peers[address] = peer = new Peer();
        return peer;
    }

    static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    // Handles one pairing connection after its "TCS1" prefix has been read.
    public async Task HandleAsync(Stream stream, IPAddress remote, CancellationToken serverToken)
    {
        var source = Normalize(remote);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(StepTimeoutSeconds * 3));
        var ct = timeout.Token;
        Window? active = null;
        var consumed = false;
        try
        {
            using var firstStep = CancellationTokenSource.CreateLinkedTokenSource(ct);
            firstStep.CancelAfter(TimeSpan.FromSeconds(StepTimeoutSeconds));
            var x = new byte[65];
            await TcsWire.ReadExactAsync(stream, x, firstStep.Token);

            PairException? refusal = null;
            lock (gate)
            {
                var now = DateTimeOffset.UtcNow;
                var peer = PeerFor(source, now);
                if (peer.BlockedUntil > now)
                    refusal = new PairException(PairResult.RateLimited, "Too many failed attempts from this address.", -1, (int)Math.Ceiling((peer.BlockedUntil - now).TotalSeconds));
                else if (now - peer.LastAttempt < TimeSpan.FromSeconds(MinSecondsBetweenAttempts))
                    refusal = new PairException(PairResult.RateLimited, "Slow down: one pairing attempt every 2 seconds.", -1, MinSecondsBetweenAttempts);
                peer.LastAttempt = now;
                if (refusal is null && window is not { } w2)
                {
                    if (now - peer.ProbeWindowStart > TimeSpan.FromMinutes(1)) { peer.ProbeWindowStart = now; peer.Probes = 0; }
                    peer.Probes++;
                    refusal = peer.Probes > ProbesPerMinute
                        ? new PairException(PairResult.RateLimited, "Too many pairing probes.", -1, 60)
                        : lastCloseReason == "expired" && now - lastClosed < TimeSpan.FromMinutes(2)
                            ? new PairException(PairResult.Expired, "The pairing window has expired. Run tcsd pair again.")
                            : lastCloseReason == "locked" && now - lastClosed < TimeSpan.FromMinutes(2)
                                ? new PairException(PairResult.Locked, "Too many wrong codes: the pairing window is locked. Run tcsd pair again.")
                                : new PairException(PairResult.NotPairing, "The controlled PC is not in pairing mode. Run tcsd pair on it.");
                }
                else if (refusal is null)
                {
                    active = window;
                    if (active!.Expires <= now) refusal = new PairException(PairResult.Expired, "The pairing window has expired. Run tcsd pair again.");
                    else if (active.AttemptsLeft <= 0) refusal = new PairException(PairResult.Locked, "Too many wrong codes: the pairing window is locked. Run tcsd pair again.");
                    else if (active.Busy) refusal = new PairException(PairResult.Busy, "Another pairing is in progress.");
                    else
                    {
                        active.Busy = true;
                        active.AttemptsLeft--;   // a started session always costs one attempt: an aborted session is also a guess
                        consumed = true;
                    }
                }
            }
            if (refusal is not null)
            {
                audit("pair-attempt", null, PairException.Name(refusal.Result), $"source={source}");
                await Task.Delay(300, ct);
                await PairWire.WriteErrorAsync(stream, refusal.Result, refusal.Message, refusal.AttemptsLeft, refusal.RetryAfterSeconds, ct);
                return;
            }

            var party = new Spake2.Party(active!.Digits, isClient: false);
            Spake2.Keys keys;
            try { keys = party.Finish(x); }
            catch (PairException bad)
            {
                await Fail(stream, active, bad.Result, bad.Message, source, ct);
                return;
            }
            using (var reply = new MemoryStream())
            {
                reply.WriteByte(0);
                reply.Write(party.Message);
                reply.Write(Spake2.Confirm(keys.ConfirmServer, "server", keys.TranscriptHash));
                await TcsWire.WriteAllAsync(stream, reply.ToArray(), ct);
            }

            using var secondStep = CancellationTokenSource.CreateLinkedTokenSource(ct);
            secondStep.CancelAfter(TimeSpan.FromSeconds(StepTimeoutSeconds));
            var confirm = new byte[32];
            await TcsWire.ReadExactAsync(stream, confirm, secondStep.Token);
            var sealedClient = await PairWire.ReadSealedAsync(stream, secondStep.Token);
            if (!CryptographicOperations.FixedTimeEquals(confirm, Spake2.Confirm(keys.ConfirmClient, "client", keys.TranscriptHash)))
            {
                await Fail(stream, active, PairResult.BadCode, "The pairing code is wrong.", source, ct);
                return;
            }

            byte[] clientBlob;
            try
            {
                clientBlob = Spake2.Open(keys, 1, sealedClient);
                Pairing.PublicLine(clientBlob);
            }
            catch (Exception exception) when (exception is PairException or InvalidDataException or ArgumentException or FormatException)
            {
                await Fail(stream, active, PairResult.ProtocolError, "The controller sent an unusable key.", source, ct);
                return;
            }

            bool already;
            try { already = authorize(clientBlob); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                await Fail(stream, active, PairResult.InternalError, "The controlled PC could not save the authorization.", source, ct);
                return;
            }
            using (var final = new MemoryStream())
            {
                final.WriteByte(0);
                final.WriteByte(already ? (byte)1 : (byte)0);
                var sealedHost = Spake2.Seal(keys, 2, hostBlob);
                final.Write(BitConverter.GetBytes((uint)sealedHost.Length));
                final.Write(sealedHost);
                await TcsWire.WriteAllAsync(stream, final.ToArray(), ct);
            }
            var fingerprint = Pairing.Fingerprint(clientBlob);
            audit("pair-ok", fingerprint, already ? "ALREADY_PAIRED" : "PAIRED", $"source={source} id={active.Id}");
            log($"Paired with controller {fingerprint} from {source}.");
            lock (gate) peers.Remove(source);
            Close(active, "paired");
            active = null;
        }
        catch (Exception exception) when (consumed && active is not null && exception is IOException or EndOfStreamException or OperationCanceledException or SocketException)
        {
            // The controller vanished or stalled after the exchange started: that was a guess, count it against the address.
            RecordFailure(source);
            audit("pair-attempt", null, "ABORTED", $"source={source} attemptsLeft={Math.Max(active.AttemptsLeft, 0)}");
            if (active.AttemptsLeft <= 0) Close(active, "locked");
        }
        finally
        {
            if (active is not null) lock (gate) active.Busy = false;
        }
    }

    void RecordFailure(IPAddress source)
    {
        lock (gate)
        {
            var peer = PeerFor(source, DateTimeOffset.UtcNow);
            if (++peer.Failures >= FailuresBeforeBlock) peer.BlockedUntil = DateTimeOffset.UtcNow.AddMinutes(BlockMinutes);
        }
    }

    async Task Fail(Stream stream, Window active, PairResult result, string text, IPAddress source, CancellationToken ct)
    {
        RecordFailure(source);
        int left;
        lock (gate) left = Math.Max(active.AttemptsLeft, 0);
        audit("pair-attempt", null, PairException.Name(result), $"source={source} attemptsLeft={left} id={active.Id}");
        log($"Pairing attempt from {source} failed: {PairException.Name(result)} ({left} attempts left).");
        await Task.Delay(750, ct);   // fixed slow-down for every failure
        await PairWire.WriteErrorAsync(stream, result, text, left, 0, ct);
        if (left <= 0) Close(active, "locked");
    }
}
