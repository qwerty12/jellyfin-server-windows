using System;
using System.Reflection;
using System.Windows.Forms;

namespace Jellyfin.Windows.Tray
{
    // Karsten: https://stackoverflow.com/a/26695961
    internal static class NotifyIconHelper
    {
        private static readonly FieldInfo windowField = typeof(NotifyIcon).GetField("window", BindingFlags.NonPublic | BindingFlags.Instance);

        public static IntPtr GetHandle(NotifyIcon icon)
        {
            if (windowField == null)
                throw new InvalidOperationException("[Useful error message]");

            NativeWindow window = (NativeWindow)windowField.GetValue(icon);
            return window.Handle;
        }

        private static readonly FieldInfo idField = typeof(NotifyIcon).GetField("id", BindingFlags.NonPublic | BindingFlags.Instance);

        public static uint GetId(NotifyIcon icon)
        {
            if (idField == null)
                throw new InvalidOperationException("[Useful error message]");

            return (uint)idField.GetValue(icon);
        }
    }
}
