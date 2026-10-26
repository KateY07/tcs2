using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Tcs;

// An always-visible, click-through, topmost badge that shows that this PC is under remote control and
// displays each command as it runs. It exists so a user physically at the machine can always see, and
// later audit, what the controller did. The daemon refuses exec/upload whenever this badge is not visible
// (no interactive desktop, window hidden, or the render thread wedged), so remote control can never run
// silently. The badge is click-through (WS_EX_TRANSPARENT), so it never gets in the user's way, and it
// re-asserts topmost + visible on every tick, so it cannot simply be hidden; ending its process stops the
// whole daemon, which is the point.
[SupportedOSPlatform("windows")]
internal sealed class WatermarkOverlay
{
    const string ClassName = "TcsWatermarkOverlay";
    const int Width = 560, Height = 116, MaxLines = 4;
    const uint WS_POPUP = 0x80000000, WS_VISIBLE = 0x10000000;
    const uint WS_EX_LAYERED = 0x00080000, WS_EX_TRANSPARENT = 0x00000020, WS_EX_TOPMOST = 0x00000008,
               WS_EX_TOOLWINDOW = 0x00000080, WS_EX_NOACTIVATE = 0x08000000;
    const uint LWA_ALPHA = 0x2;
    const int WM_PAINT = 0x000F, WM_TIMER = 0x0113, WM_DISPLAYCHANGE = 0x007E;
    const uint SWP_NOMOVE = 0x2, SWP_NOSIZE = 0x1, SWP_NOACTIVATE = 0x10;
    const int SW_SHOWNA = 8;
    static readonly IntPtr HWND_TOPMOST = new(-1);

    readonly object gate = new();
    readonly string header;
    readonly LinkedList<string> lines = new();
    volatile IntPtr hwnd;
    volatile bool running;
    DateTime lastTick = DateTime.MinValue;
    WndProc? wndProcKeepAlive;
    Thread? thread;

    internal WatermarkOverlay(string header) => this.header = header;

    internal void Start()
    {
        thread = new Thread(ThreadMain) { IsBackground = true, Name = "tcs-watermark" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        for (var i = 0; i < 100 && hwnd == IntPtr.Zero; i++) Thread.Sleep(20);   // let the window come up before the first request
    }

    // Healthy = there is a visible window on an interactive desktop and the render thread ticked within the last 3 s.
    internal bool IsHealthy
    {
        get
        {
            var h = hwnd;
            if (!running || h == IntPtr.Zero || !IsWindowVisible(h)) return false;
            lock (gate) return DateTime.UtcNow - lastTick < TimeSpan.FromSeconds(3);
        }
    }

    internal void Push(string line)
    {
        lock (gate)
        {
            lines.AddFirst($"{DateTimeOffset.Now:HH:mm:ss}  {line}");
            while (lines.Count > MaxLines) lines.RemoveLast();
        }
        var h = hwnd;
        if (h != IntPtr.Zero) InvalidateRect(h, IntPtr.Zero, true);   // InvalidateRect is safe to call across threads
    }

    void ThreadMain()
    {
        wndProcKeepAlive = WindowProc;
        var module = GetModuleHandleW(null);
        var wc = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(wndProcKeepAlive),
            hInstance = module,
            hCursor = LoadCursorW(IntPtr.Zero, 32512),   // IDC_ARROW
            lpszClassName = ClassName,
        };
        RegisterClassExW(ref wc);

        int vx = GetSystemMetrics(76), vw = GetSystemMetrics(78);   // SM_XVIRTUALSCREEN, SM_CXVIRTUALSCREEN
        var x = vx + (vw - Width) / 2;
        var created = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            ClassName, "TCS remote control", WS_POPUP | WS_VISIBLE,
            x, 12, Width, Height, IntPtr.Zero, IntPtr.Zero, module, IntPtr.Zero);
        if (created == IntPtr.Zero) { running = false; return; }

        SetLayeredWindowAttributes(created, 0, 210, LWA_ALPHA);
        SetWindowPos(created, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SetTimer(created, 1, 1000, IntPtr.Zero);
        lock (gate) lastTick = DateTime.UtcNow;
        hwnd = created;
        running = true;

        while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
        running = false;
    }

    IntPtr WindowProc(IntPtr h, uint msg, IntPtr wParam, IntPtr lParam)
    {
        switch (msg)
        {
            case WM_TIMER:
                lock (gate) lastTick = DateTime.UtcNow;
                ShowWindow(h, SW_SHOWNA);   // re-assert: a hide attempt is undone on the next tick
                SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                InvalidateRect(h, IntPtr.Zero, false);
                return IntPtr.Zero;
            case WM_DISPLAYCHANGE:
            {
                int vx = GetSystemMetrics(76), vw = GetSystemMetrics(78);
                SetWindowPos(h, HWND_TOPMOST, vx + (vw - Width) / 2, 12, Width, Height, SWP_NOACTIVATE);
                return IntPtr.Zero;
            }
            case WM_PAINT:
                Paint(h);
                return IntPtr.Zero;
        }
        return DefWindowProcW(h, msg, wParam, lParam);
    }

    void Paint(IntPtr h)
    {
        var hdc = BeginPaint(h, out var ps);
        try
        {
            GetClientRect(h, out var rc);
            var panel = CreateSolidBrush(0x141212);   // BGR dark slate
            FillRect(hdc, ref rc, panel);
            DeleteObject(panel);

            SetBkMode(hdc, 1);   // TRANSPARENT

            var title = CreateFontW(-19, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
            var oldFont = SelectObject(hdc, title);
            SetTextColor(hdc, 0x66E07A);   // BGR soft green
            var dot = $"●  TCS remote control active — {header}";
            var line = new RECT { left = rc.left + 14, top = rc.top + 10, right = rc.right - 14, bottom = rc.top + 36 };
            DrawTextW(hdc, dot, dot.Length, ref line, 0x20 | 0x4 | 0x0800 | 0x8000);   // SINGLELINE|VCENTER|NOPREFIX|END_ELLIPSIS

            var body = CreateFontW(-16, 0, 0, 0, 500, 0, 0, 0, 1, 0, 0, 5, 0, "Consolas");
            SelectObject(hdc, body);
            SetTextColor(hdc, 0xE8E8E8);
            string[] snapshot;
            lock (gate) snapshot = lines.Count == 0 ? new[] { "waiting for commands..." } : lines.ToArray();
            var y = rc.top + 40;
            foreach (var text in snapshot)
            {
                var r = new RECT { left = rc.left + 14, top = y, right = rc.right - 12, bottom = y + 18 };
                DrawTextW(hdc, text, text.Length, ref r, 0x20 | 0x0800 | 0x8000);   // SINGLELINE|NOPREFIX|END_ELLIPSIS
                y += 18;
            }

            SelectObject(hdc, oldFont);
            DeleteObject(title);
            DeleteObject(body);
        }
        finally { EndPaint(h, ref ps); }
    }

    delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)] struct RECT { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int x, y; }
    [StructLayout(LayoutKind.Sequential)] struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)] struct PAINTSTRUCT { public IntPtr hdc; public int fErase; public RECT rcPaint; public int fRestore, fIncUpdate; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] rgbReserved; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WNDCLASSEXW
    {
        public uint cbSize, style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra, cbWndExtra;
        public IntPtr hInstance, hIcon, hCursor, hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszClassName;
        public IntPtr hIconSm;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandleW(string? name);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern ushort RegisterClassExW(ref WNDCLASSEXW c);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr CreateWindowExW(uint exStyle, string cls, string name, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32")] static extern bool SetLayeredWindowAttributes(IntPtr h, uint key, byte alpha, uint flags);
    [DllImport("user32")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32")] static extern IntPtr SetTimer(IntPtr h, IntPtr id, uint ms, IntPtr func);
    [DllImport("user32")] static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32")] static extern bool InvalidateRect(IntPtr h, IntPtr rect, bool erase);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern int GetMessageW(out MSG msg, IntPtr h, uint min, uint max);
    [DllImport("user32")] static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr DispatchMessageW(ref MSG msg);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr DefWindowProcW(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr LoadCursorW(IntPtr inst, int id);
    [DllImport("user32")] static extern int GetSystemMetrics(int index);
    [DllImport("user32")] static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32")] static extern IntPtr BeginPaint(IntPtr h, out PAINTSTRUCT ps);
    [DllImport("user32")] static extern bool EndPaint(IntPtr h, ref PAINTSTRUCT ps);
    [DllImport("user32")] static extern int FillRect(IntPtr hdc, ref RECT r, IntPtr brush);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern int DrawTextW(IntPtr hdc, string text, int count, ref RECT r, uint format);
    [DllImport("gdi32")] static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("gdi32")] static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
    [DllImport("gdi32")] static extern int SetBkMode(IntPtr hdc, int mode);
    [DllImport("gdi32")] static extern uint SetTextColor(IntPtr hdc, uint color);
    [DllImport("gdi32", CharSet = CharSet.Unicode)] static extern IntPtr CreateFontW(int height, int width, int esc, int orient, int weight, uint italic, uint underline, uint strike, uint charset, uint outPrec, uint clipPrec, uint quality, uint pitch, string face);
}
