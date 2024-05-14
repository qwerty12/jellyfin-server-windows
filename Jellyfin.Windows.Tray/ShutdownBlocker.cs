using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Jellyfin.Windows.Tray
{
    internal sealed class ShutdownBlocker : NativeWindow
    {
        // Pilfered from EarTrumpet and https://www.meziantou.net/prevent-windows-shutdown-or-session-ending-in-dotnet.htm
        public const int WM_QUERYENDSESSION = 0x0011;
        public const int WM_ENDSESSION = 0x0016;
        public const uint SHUTDOWN_NORETRY = 0x00000001;
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool ShutdownBlockReasonCreate(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string reason);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool ShutdownBlockReasonDestroy(IntPtr hWnd);
        [DllImport("kernel32.dll")]
        static extern bool SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

        private Action shutdownCallback;
        public string BlockMsg { get; set; } = string.Empty;
        public bool Block { get; set; } = false;

        public ShutdownBlocker(NotifyIcon parent, Action fnShutdownCallback)
        {
            shutdownCallback = fnShutdownCallback;
            AssignHandle(NotifyIconHelper.GetHandle(parent));
            parent.Disposed += this.OnHandleDestroyed;
            SetProcessShutdownParameters(0x3FF, SHUTDOWN_NORETRY);
        }

        ~ShutdownBlocker()
        {
            shutdownCallback = null;
            ReleaseHandle();
        }

        protected override void WndProc(ref Message m)
        {
            if (Block)
            {
                if (m.Msg == WM_QUERYENDSESSION || m.Msg == WM_ENDSESSION)
                {
                    ShutdownBlockReasonCreate(this.Handle, BlockMsg);
                    try
                    {
                        this.shutdownCallback();
                    }
                    catch
                    {
                        // ignored
                    }
                    ShutdownBlockReasonDestroy(this.Handle);
                    Application.Exit();

                    return;
                }
            }

            base.WndProc(ref m);
        }

        internal void OnHandleDestroyed(object sender, EventArgs e)
        {
            ReleaseHandle();
        }
    }
}
