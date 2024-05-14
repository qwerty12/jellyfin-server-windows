#pragma warning disable CS1591

using System;
using System.Runtime.InteropServices;

namespace Jellyfin.Windows.Tray;

public static class ConsoleHelpers
{
    public enum HandlerRoutineCtrls : uint
    {
        CTRL_C_EVENT = 0
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AttachConsole(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleCtrlHandler(IntPtr handlerRoutine, bool add);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GenerateConsoleCtrlEvent(HandlerRoutineCtrls dwCtrlEvent, uint dwProcessGroupId);
}
