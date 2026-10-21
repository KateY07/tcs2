using System.Text;

namespace Tcs;

// Bounds remote exec output so a chatty script cannot flood the caller's context (or the daemon's memory).
// Keeps the first quarter and the last three quarters of the allowed characters; the rest is counted and dropped.
internal static class OutputCap
{
    internal const int DefaultLimit = 16000;

    internal static async Task<(string Text, long Omitted)> ReadAsync(TextReader reader, int limit, CancellationToken cancellationToken)
    {
        if (limit <= 0) return (await reader.ReadToEndAsync(cancellationToken), 0);
        var headSize = limit / 4;
        var tailSize = limit - headSize;
        var head = new StringBuilder(headSize);
        var tail = new char[tailSize];
        var buffer = new char[8192];
        long total = 0;
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            for (var i = 0; i < read; i++, total++)
            {
                if (total < headSize) head.Append(buffer[i]);
                else tail[(total - headSize) % tailSize] = buffer[i];
            }
        }
        if (total <= limit)
        {
            var kept = (int)Math.Max(0, total - headSize);
            return (head.Append(tail, 0, kept).ToString(), 0);
        }
        var first = (int)((total - headSize) % tailSize);
        var tailText = new string([.. tail.AsSpan(first), .. tail.AsSpan(0, first)]);
        var omitted = total - limit;
        if (head.Length > 0 && char.IsHighSurrogate(head[^1])) { head.Length--; omitted++; }
        if (tailText.Length > 0 && char.IsLowSurrogate(tailText[0])) { tailText = tailText[1..]; omitted++; }
        return ($"{head}\n...[tcs: {omitted} characters omitted; filter or summarize the output in your script, or add --max-output 0]...\n{tailText}", omitted);
    }
}
