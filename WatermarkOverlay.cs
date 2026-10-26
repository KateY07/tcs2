using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Tcs;

// An unobtrusive but always-present proof that this PC can be driven remotely, shown on its own desktop: small
// white text with a soft shadow, transparent background, parked at the right edge, vertically centred. It shows
// the few most recent commands; full detail (the audit log) and Exit are on the tray icon. It exists so the
// "service" form of tcsd is never covert: when this badge is not healthy (no interactive desktop, window hidden,
// or its UI thread stuck) exec/upload are refused.
//
// The badge cannot be made truly unkillable - any process can be ended - so the design is "fail visible, fail
// closed": it re-asserts topmost/visible every second, is click-through (WS_EX_TRANSPARENT), and the daemon
// refuses to act the moment it stops being healthy. Per-pixel alpha (UpdateLayeredWindow) keeps it faint.
[SupportedOSPlatform("windows")]
internal sealed class WatermarkOverlay
{
    const string ClassName = "TcsWatermarkOverlay";
    const string Title = "● TCS remote control";
    const int Width = 300, Height = 60, MaxLines = 2, MarginRight = 26;
    const double TextOpacity = 0.72, ShadowOpacity = 0.55;   // kept low on purpose: visible, not loud
    const uint WS_POPUP = 0x80000000;
    const uint WS_EX_LAYERED = 0x00080000, WS_EX_TRANSPARENT = 0x00000020, WS_EX_TOPMOST = 0x00000008,
               WS_EX_TOOLWINDOW = 0x00000080, WS_EX_NOACTIVATE = 0x08000000;
    const int WM_PAINT = 0x000F, WM_TIMER = 0x0113, WM_TRAY = 0x0400 + 1;   // WM_APP+1
    const int WM_LBUTTONUP = 0x0202, WM_RBUTTONUP = 0x0205;
    const uint SWP_NOMOVE = 0x2, SWP_NOSIZE = 0x1, SWP_NOACTIVATE = 0x10;
    const int SW_SHOWNA = 8;
    const uint ULW_ALPHA = 0x2;
    const byte AC_SRC_OVER = 0, AC_SRC_ALPHA = 1;
    const uint NIM_ADD = 0, NIM_DELETE = 2, NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4;
    const uint TPM_RIGHTBUTTON = 0x2, TPM_RETURNCMD = 0x100, MF_STRING = 0, MF_SEPARATOR = 0x800, MF_GRAYED = 0x1;
    const uint CmdAudit = 1, CmdExit = 2;
    static readonly IntPtr HWND_TOPMOST = new(-1);

    readonly object gate = new();
    readonly string header;      // host fingerprint, shown in the tray tooltip/menu
    readonly string auditPath;
    readonly LinkedList<string> lines = new();
    volatile IntPtr hwnd;         // the layered badge
    IntPtr trayHwnd;              // hidden sink for the tray icon + menu
    volatile bool running;
    DateTime lastTick = DateTime.MinValue;
    WndProc? wndProcKeepAlive;
    Thread? thread;
    NOTIFYICONDATAW nid;
    bool trayAdded;

    internal WatermarkOverlay(string header, string auditPath)
    {
        this.header = header;
        this.auditPath = auditPath;
    }

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
        if (h != IntPtr.Zero) InvalidateRect(h, IntPtr.Zero, false);   // InvalidateRect is safe to call across threads
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

        var created = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            ClassName, "TCS remote control", WS_POPUP,
            0, 0, Width, Height, IntPtr.Zero, IntPtr.Zero, module, IntPtr.Zero);
        if (created == IntPtr.Zero) { running = false; return; }
        hwnd = created;
        RenderAndUpdate(created);
        ShowWindow(created, SW_SHOWNA);
        SetWindowPos(created, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SetTimer(created, 1, 1000, IntPtr.Zero);

        trayHwnd = CreateWindowExW(0, ClassName, "TCS tray", WS_POPUP, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, module, IntPtr.Zero);
        AddTrayIcon(module);

        lock (gate) lastTick = DateTime.UtcNow;
        running = true;

        while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
        running = false;
    }

    void AddTrayIcon(IntPtr module)
    {
        var exe = Environment.ProcessPath;
        var icon = exe is null ? IntPtr.Zero : ExtractIconW(module, exe, 0);
        if (icon == IntPtr.Zero || icon == new IntPtr(1)) icon = LoadIconW(IntPtr.Zero, 32512);   // IDI_APPLICATION fallback
        nid = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = trayHwnd,
            uID = 1,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAY,
            hIcon = icon,
            szTip = $"TCS remote control active — {header}",
            szInfo = "",
            szInfoTitle = "",
        };
        trayAdded = Shell_NotifyIconW(NIM_ADD, ref nid);
    }

    IntPtr WindowProc(IntPtr h, uint msg, IntPtr wParam, IntPtr lParam)
    {
        switch (msg)
        {
            case WM_TIMER:
                lock (gate) lastTick = DateTime.UtcNow;
                ShowWindow(hwnd, SW_SHOWNA);   // re-assert: a hide attempt is undone on the next tick
                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                RenderAndUpdate(hwnd);
                return IntPtr.Zero;
            case WM_PAINT:
                ValidateRect(hwnd, IntPtr.Zero);
                RenderAndUpdate(hwnd);
                return IntPtr.Zero;
            case WM_TRAY:
                if ((int)lParam is WM_LBUTTONUP or WM_RBUTTONUP) ShowTrayMenu();
                return IntPtr.Zero;
        }
        return DefWindowProcW(h, msg, wParam, lParam);
    }

    void ShowTrayMenu()
    {
        var menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, "This PC can be driven remotely by TCS");
        AppendMenuW(menu, MF_SEPARATOR, 0, null);
        AppendMenuW(menu, MF_STRING, (UIntPtr)CmdAudit, "Open audit log (details)");
        AppendMenuW(menu, MF_STRING, (UIntPtr)CmdExit, "Exit — stop tcsd");
        GetCursorPos(out var pt);
        SetForegroundWindow(trayHwnd);   // so the menu closes when the user clicks elsewhere
        var cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, trayHwnd, IntPtr.Zero);
        DestroyMenu(menu);
        if ((uint)cmd == CmdAudit)
        {
            var target = File.Exists(auditPath) ? auditPath : Path.GetDirectoryName(auditPath) ?? auditPath;
            ShellExecuteW(IntPtr.Zero, "open", target, null, null, 1);
        }
        else if ((uint)cmd == CmdExit)
        {
            if (trayAdded) Shell_NotifyIconW(NIM_DELETE, ref nid);
            Environment.Exit(0);
        }
    }

    // Renders the badge into a 32-bpp premultiplied DIB (white text + soft shadow, transparent elsewhere) and
    // blends it onto the screen with per-pixel alpha. Positioned at the right edge, vertically centred.
    void RenderAndUpdate(IntPtr h)
    {
        var screenDC = GetDC(IntPtr.Zero);
        var memDC = CreateCompatibleDC(screenDC);
        var bmi = new BITMAPINFOHEADER
        {
            biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
            biWidth = Width, biHeight = -Height, biPlanes = 1, biBitCount = 32, biCompression = 0,
        };
        var dib = CreateDIBSection(memDC, ref bmi, 0, out var bits, IntPtr.Zero, 0);
        if (dib == IntPtr.Zero) { DeleteDC(memDC); ReleaseDC(IntPtr.Zero, screenDC); return; }
        var oldBmp = SelectObject(memDC, dib);

        // 1. draw all text opaque white on a black (zeroed) DIB; the grey level is the text coverage.
        SetBkMode(memDC, 1);   // TRANSPARENT
        SetTextColor(memDC, 0x00FFFFFF);
        var titleFont = CreateFontW(-12, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
        var bodyFont = CreateFontW(-11, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
        var old = SelectObject(memDC, titleFont);
        DrawLine(memDC, Title, 8, 4, Width - 12, 16);
        SelectObject(memDC, bodyFont);
        string[] snapshot;
        lock (gate) snapshot = lines.Count == 0 ? new[] { "waiting for commands…" } : lines.ToArray();
        var y = 22;
        foreach (var text in snapshot) { DrawLine(memDC, text, 8, y, Width - 10, 14); y += 15; }
        SelectObject(memDC, old);
        DeleteObject(titleFont);
        DeleteObject(bodyFont);

        // 2. coverage = luminance of the white render.
        var raw = new byte[Width * Height * 4];
        Marshal.Copy(bits, raw, 0, raw.Length);
        var cov = new byte[Width * Height];
        for (int i = 0, p = 0; p < cov.Length; i += 4, p++)
            cov[p] = Math.Max(raw[i], Math.Max(raw[i + 1], raw[i + 2]));

        // 3. white text premultiplied over a black shadow offset down-right; everything else stays transparent.
        for (int yy = 0, p = 0; yy < Height; yy++)
        {
            for (var xx = 0; xx < Width; xx++, p++)
            {
                byte sc = 0;
                foreach (var (dx, dy) in Shadow)
                {
                    int sx = xx - dx, sy = yy - dy;
                    if (sx >= 0 && sy >= 0) sc = Math.Max(sc, cov[sy * Width + sx]);
                }
                var tA = cov[p] / 255.0 * TextOpacity;
                var sA = sc / 255.0 * ShadowOpacity;
                var a = tA + sA * (1 - tA);
                var c = (byte)(255 * tA);
                var o = p * 4;
                raw[o] = raw[o + 1] = raw[o + 2] = c;   // premultiplied white
                raw[o + 3] = (byte)(255 * a);
            }
        }
        Marshal.Copy(raw, 0, bits, raw.Length);

        // 4. blend onto the screen at the right edge, vertically centred on the virtual desktop.
        int vx = GetSystemMetrics(76), vy = GetSystemMetrics(77), vw = GetSystemMetrics(78), vh = GetSystemMetrics(79);
        var dst = new POINT { x = vx + vw - Width - MarginRight, y = vy + (vh - Height) / 2 };
        var size = new SIZE { cx = Width, cy = Height };
        var src = new POINT { x = 0, y = 0 };
        var blend = new BLENDFUNCTION { BlendOp = AC_SRC_OVER, BlendFlags = 0, SourceConstantAlpha = 255, AlphaFormat = AC_SRC_ALPHA };
        UpdateLayeredWindow(h, screenDC, ref dst, ref size, memDC, ref src, 0, ref blend, ULW_ALPHA);

        SelectObject(memDC, oldBmp);
        DeleteObject(dib);
        DeleteDC(memDC);
        ReleaseDC(IntPtr.Zero, screenDC);
    }

    static readonly (int dx, int dy)[] Shadow = { (1, 1), (2, 2), (1, 2), (2, 1) };

    void DrawLine(IntPtr hdc, string text, int x, int y, int w, int hgt)
    {
        var r = new RECT { left = x, top = y, right = x + w, bottom = y + hgt };
        DrawTextW(hdc, text, text.Length, ref r, 0x20 | 0x0800 | 0x8000);   // SINGLELINE|NOPREFIX|END_ELLIPSIS
    }

    delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)] struct RECT { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int x, y; }
    [StructLayout(LayoutKind.Sequential)] struct SIZE { public int cx, cy; }
    [StructLayout(LayoutKind.Sequential)] struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)] struct BLENDFUNCTION { public byte BlendOp, BlendFlags, SourceConstantAlpha, AlphaFormat; }

    [StructLayout(LayoutKind.Sequential)]
    struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth, biHeight;
        public ushort biPlanes, biBitCount;
        public uint biCompression, biSizeImage;
        public int biXPelsPerMeter, biYPelsPerMeter;
        public uint biClrUsed, biClrImportant;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID, uFlags, uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState, dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

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
    [DllImport("user32")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32")] static extern IntPtr SetTimer(IntPtr h, IntPtr id, uint ms, IntPtr func);
    [DllImport("user32")] static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32")] static extern bool InvalidateRect(IntPtr h, IntPtr rect, bool erase);
    [DllImport("user32")] static extern bool ValidateRect(IntPtr h, IntPtr rect);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern int GetMessageW(out MSG msg, IntPtr h, uint min, uint max);
    [DllImport("user32")] static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr DispatchMessageW(ref MSG msg);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr DefWindowProcW(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr LoadCursorW(IntPtr inst, int id);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern IntPtr LoadIconW(IntPtr inst, int id);
    [DllImport("user32")] static extern int GetSystemMetrics(int index);
    [DllImport("user32")] static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("user32")] static extern bool UpdateLayeredWindow(IntPtr h, IntPtr dst, ref POINT pptDst, ref SIZE psize, IntPtr src, ref POINT pptSrc, uint crKey, ref BLENDFUNCTION blend, uint flags);
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern int DrawTextW(IntPtr hdc, string text, int count, ref RECT r, uint format);
    [DllImport("user32")] static extern IntPtr CreatePopupMenu();
    [DllImport("user32", CharSet = CharSet.Unicode)] static extern bool AppendMenuW(IntPtr menu, uint flags, UIntPtr id, string? item);
    [DllImport("user32")] static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr h, IntPtr rect);
    [DllImport("user32")] static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32")] static extern bool GetCursorPos(out POINT p);
    [DllImport("user32")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("gdi32")] static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    [DllImport("gdi32")] static extern bool DeleteDC(IntPtr hdc);
    [DllImport("gdi32")] static extern IntPtr CreateDIBSection(IntPtr hdc, ref BITMAPINFOHEADER bmi, uint usage, out IntPtr bits, IntPtr section, uint offset);
    [DllImport("gdi32")] static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
    [DllImport("gdi32")] static extern int SetBkMode(IntPtr hdc, int mode);
    [DllImport("gdi32")] static extern uint SetTextColor(IntPtr hdc, uint color);
    [DllImport("gdi32", CharSet = CharSet.Unicode)] static extern IntPtr CreateFontW(int height, int width, int esc, int orient, int weight, uint italic, uint underline, uint strike, uint charset, uint outPrec, uint clipPrec, uint quality, uint pitch, string face);
    [DllImport("shell32", CharSet = CharSet.Unicode)] static extern bool Shell_NotifyIconW(uint message, ref NOTIFYICONDATAW data);
    [DllImport("shell32", CharSet = CharSet.Unicode)] static extern IntPtr ExtractIconW(IntPtr inst, string exe, uint index);
    [DllImport("shell32", CharSet = CharSet.Unicode)] static extern IntPtr ShellExecuteW(IntPtr h, string? op, string file, string? parameters, string? dir, int show);
}
