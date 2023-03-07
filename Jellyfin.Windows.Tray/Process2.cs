// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// With additional thanks to https://github.com/Albeoris/Septerra/tree/master/Septerra/Hooks/CustomProcess

// 'Cause System.Diagnostics.Process lets you do everything except for redirecting stdout etc. to NUL. Faark me.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Permissions;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Jellyfin.Windows.Tray;

[HostProtection(MayLeakOnAbort = true)]
internal static class NativeMethods
{
    public const int GENERIC_WRITE = 0x40000000;

    public const int FILE_SHARE_READ = 0x00000001;
    public const int FILE_SHARE_WRITE = 0x00000002;
    public const int FILE_SHARE_DELETE = 0x00000004;

    public const int STARTF_USESTDHANDLES = 0x00000100;

    public const int ERROR_BAD_EXE_FORMAT = 193;
    public const int ERROR_EXE_MACHINE_TYPE_MISMATCH = 216;

    public const int CREATE_NO_WINDOW = 0x08000000;

    public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    internal class STARTUPINFOEX
    {
        public int cb;
        public IntPtr lpReserved = IntPtr.Zero;
        public IntPtr lpDesktop = IntPtr.Zero;
        public IntPtr lpTitle = IntPtr.Zero;
        public int dwX = 0;
        public int dwY = 0;
        public int dwXSize = 0;
        public int dwYSize = 0;
        public int dwXCountChars = 0;
        public int dwYCountChars = 0;
        public int dwFillAttribute = 0;
        public int dwFlags = 0;
        public short wShowWindow = 0;
        public short cbReserved2 = 0;
        public IntPtr lpReserved2 = IntPtr.Zero;
        public SafeFileHandle hStdInput = new(IntPtr.Zero, false);
        public SafeFileHandle hStdOutput = new(IntPtr.Zero, false);
        public SafeFileHandle hStdError = new(IntPtr.Zero, false);
        public SafeProcThreadAttributeList lpAttributeList = null;

        public STARTUPINFOEX()
        {
            cb = Marshal.SizeOf(this);
        }

        public void Dispose()
        {
            // close the handles created for child process
            if (hStdInput != null && !hStdInput.IsInvalid)
            {
                hStdInput.Close();
                hStdInput = null;
            }

            if (hStdOutput != null && !hStdOutput.IsInvalid)
            {
                hStdOutput.Close();
                hStdOutput = null;
            }

            if (hStdError != null && !hStdError.IsInvalid)
            {
                hStdError.Close();
                hStdError = null;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor = IntPtr.Zero;
        public bool bInheritHandle = false;

        public SECURITY_ATTRIBUTES()
        {
            nLength = Marshal.SizeOf((object)this);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true, BestFitMapping = false)]
    [ResourceExposure(ResourceScope.Process)]
    public static extern bool CreateProcess(
        [MarshalAs(UnmanagedType.LPTStr)] string lpApplicationName, // LPCTSTR
        StringBuilder lpCommandLine, // LPTSTR - note: CreateProcess might insert a null somewhere in this string
        SECURITY_ATTRIBUTES lpProcessAttributes, // LPSECURITY_ATTRIBUTES
        SECURITY_ATTRIBUTES lpThreadAttributes, // LPSECURITY_ATTRIBUTES
        bool bInheritHandles, // BOOL
        int dwCreationFlags, // DWORD
        IntPtr lpEnvironment, // LPVOID
        [MarshalAs(UnmanagedType.LPTStr)] string lpCurrentDirectory, // LPCTSTR
        STARTUPINFOEX lpStartupInfo, // LPSTARTUPINFO
        SafeNativeMethods.PROCESS_INFORMATION lpProcessInformation // LPPROCESS_INFORMATION
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, BestFitMapping = false)]
    [ResourceExposure(ResourceScope.Machine)]
    public static extern SafeFileHandle CreateFile(string lpFileName, int dwDesiredAccess, int dwShareMode, SECURITY_ATTRIBUTES lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);
}

[HostProtection(MayLeakOnAbort = true)]
[SuppressUnmanagedCodeSecurity]
internal static class SafeNativeMethods
{
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    internal class PROCESS_INFORMATION
    {
        public IntPtr hProcess = IntPtr.Zero;
        public IntPtr hThread = IntPtr.Zero;
        public int dwProcessId = 0;
        public int dwThreadId = 0;
    }
}

[HostProtection(MayLeakOnAbort = true)]
[SuppressUnmanagedCodeSecurity]
internal static class UnsafeNativeMethods
{
    public const int OPEN_EXISTING = 3;
}

[SuppressUnmanagedCodeSecurity]
internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeThreadHandle() : base(true)
    {
    }

    internal void InitialSetHandle(IntPtr h)
    {
        Debug.Assert(IsInvalid, "Safe handle should only be set once");
        SetHandle(h);
    }

    protected override bool ReleaseHandle()
    {
        return SafeNativeMethods.CloseHandle(handle);
    }
}

internal sealed class SafeProcThreadAttributeList : SafeBuffer
{
    public const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    // https://github.com/ificator/ManagedSandbox/blob/master/src/Native/SafeProcThreadAttributeList.cs
    public SafeProcThreadAttributeList(uint attributeCount) : base(ownsHandle: true)
    {
        IntPtr size = new IntPtr(0);
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

        this.handle = Marshal.AllocHGlobal(size);

        if (!InitializeProcThreadAttributeList(this.handle, attributeCount, 0, ref size))
        {
            Marshal.FreeHGlobal(this.handle);
            throw new Win32Exception();
        }
    }

    private enum PROC_THREAD_ATTRIBUTES : uint
    {
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002,
    }

    public void UpdateHandleList(IntPtr[] handles)
    {
        if (!UpdateProcThreadAttribute(this, 0, PROC_THREAD_ATTRIBUTES.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, (uint)(IntPtr.Size * handles.Length), IntPtr.Zero, IntPtr.Zero))
        {
            throw new Win32Exception();
        }
    }

    protected override bool ReleaseHandle()
    {
        if (!this.IsInvalid)
        {
            DeleteProcThreadAttributeList(this.handle);
            Marshal.FreeHGlobal(this.handle);
            this.handle = IntPtr.Zero;
        }

        return true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        uint dwAttributeCount,
        uint dwFlags,
        ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        SafeProcThreadAttributeList lpAttributeList,
        uint dwFlags,
        PROC_THREAD_ATTRIBUTES attribute,
        IntPtr[] lpValue,
        uint cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);
}

internal sealed class Process2 : Process
{
    private static readonly Type ProcessType = typeof(Process);
    private static readonly object s_CreateProcessLock = ProcessType.GetField("s_CreateProcessLock", BindingFlags.Static | BindingFlags.NonPublic)?.GetValue(null) ?? new object();
    private static readonly MethodInfo SetProcessHandle = ProcessType.GetMethod("SetProcessHandle", BindingFlags.Instance | BindingFlags.NonPublic);
    private static readonly MethodInfo SetProcessId = ProcessType.GetMethod("SetProcessId", BindingFlags.Instance | BindingFlags.NonPublic);
    private bool disposed;

    public bool Start()
    {
        Close();

        var startInfo = StartInfo;
        if (startInfo.FileName.Length == 0)
        {
            throw new InvalidOperationException("FileNameMissing");
        }

        if (startInfo.UseShellExecute)
        {
            throw new NotSupportedException("startInfo.UseShellExecute");
        }

        return StartWithCreateProcess(startInfo);
    }

    protected override void Dispose(bool disposing)
    {
        if (!disposed)
        {
            disposed = true;
            base.Dispose(disposing);
        }
    }

    private static StringBuilder BuildCommandLine(string executableFileName, string arguments)
    {
        // Construct a StringBuilder with the appropriate command line
        // to pass to CreateProcess.  If the filename isn't already
        // in quotes, we quote it here.  This prevents some security
        // problems (it specifies exactly which part of the string
        // is the file to execute).
        var commandLine = new StringBuilder();
        var fileName = executableFileName.Trim();
        var fileNameIsQuoted = fileName.StartsWith("\"", StringComparison.Ordinal) && fileName.EndsWith("\"", StringComparison.Ordinal);
        if (!fileNameIsQuoted)
        {
            commandLine.Append("\"");
        }

        commandLine.Append(fileName);

        if (!fileNameIsQuoted)
        {
            commandLine.Append("\"");
        }

        if (!String.IsNullOrEmpty(arguments))
        {
            commandLine.Append(" ");
            commandLine.Append(arguments);
        }

        return commandLine;
    }

    private bool StartWithCreateProcess(ProcessStartInfo startInfo)
    {
        // See knowledge base article Q190351 for an explanation of the following code.

        // Cannot start a new process and store its handle if the object has been disposed, since finalization has been suppressed.
        if (disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }

        var commandLine = BuildCommandLine(startInfo.FileName, startInfo.Arguments);

        var startupInfo = new NativeMethods.STARTUPINFOEX();
        var processInfo = new SafeNativeMethods.PROCESS_INFORMATION();
        SafeProcessHandle procSH = null;
        var threadSH = new SafeThreadHandle();
        var errorCode = 0;
        SafeProcThreadAttributeList attributeList = null;
        SafeFileHandle[] inheritableHandles = null;
        IntPtr[] inheritableHandlesMarshallable;
        lock (s_CreateProcessLock)
        {
            if (startInfo.RedirectStandardInput)
            {
                throw new NotSupportedException("startInfo.RedirectStandardInput");
            }

            try
            {
                var creationFlags = 0;

                // set up the streams
                if (startInfo.RedirectStandardOutput || startInfo.RedirectStandardError)
                {
                    attributeList = new SafeProcThreadAttributeList(1);
                    inheritableHandles = new[]
                    {
                        NativeMethods.CreateFile("NUL", NativeMethods.GENERIC_WRITE, NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE, new NativeMethods.SECURITY_ATTRIBUTES() { bInheritHandle = true }, UnsafeNativeMethods.OPEN_EXISTING, 0, IntPtr.Zero)
                    };
                    if (inheritableHandles.Any(h => h.IsInvalid))
                    {
                        throw new Win32Exception();
                    }

                    if (startInfo.RedirectStandardOutput)
                    {
                        startupInfo.hStdOutput = inheritableHandles[0];
                    }

                    if (startInfo.RedirectStandardError)
                    {
                        startupInfo.hStdError = inheritableHandles[0];
                    }

                    startupInfo.dwFlags = NativeMethods.STARTF_USESTDHANDLES;

                    inheritableHandlesMarshallable = new IntPtr[inheritableHandles.Length];
                    for (int i = 0; i < inheritableHandlesMarshallable.Length; ++i)
                    {
                        inheritableHandlesMarshallable[i] = inheritableHandles[i].DangerousGetHandle();
                    }
                    //GC.KeepAlive(inheritableHandlesMarshallable);
                    attributeList.UpdateHandleList(inheritableHandlesMarshallable);
                    startupInfo.lpAttributeList = attributeList;
                    creationFlags = SafeProcThreadAttributeList.EXTENDED_STARTUPINFO_PRESENT;
                }

                if (startInfo.CreateNoWindow)
                {
                    creationFlags |= NativeMethods.CREATE_NO_WINDOW;
                }

                var environmentPtr = (IntPtr)0;
                if (typeof(ProcessStartInfo).GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(startInfo) != null)
                {
                    throw new NotSupportedException("startInfo.environmentVariables != null");
                }

                var workingDirectory = startInfo.WorkingDirectory;
                if (workingDirectory == string.Empty)
                {
                    workingDirectory = Environment.CurrentDirectory;
                }

                if (startInfo.UserName.Length != 0)
                {
                    throw new NotSupportedException("startInfo.UserName.Length != 0");
                }
                else
                {
                    RuntimeHelpers.PrepareConstrainedRegions();
                    bool retVal;
                    try { }
                    finally
                    {
                        retVal = NativeMethods.CreateProcess(
                            startInfo.FileName,
                            commandLine, // pointer to the command line string
                            null, // pointer to process security attributes, we don't need to inheriat the handle
                            null, // pointer to thread security attributes
                            true, // handle inheritance flag
                            creationFlags, // creation flags
                            environmentPtr, // pointer to new environment block
                            workingDirectory, // pointer to current directory name
                            startupInfo, // pointer to STARTUPINFO
                            processInfo // pointer to PROCESS_INFORMATION
                        );
                        if (!retVal)
                        {
                            errorCode = Marshal.GetLastWin32Error();
                        }

                        if (processInfo.hProcess != (IntPtr)0 && processInfo.hProcess != (IntPtr)NativeMethods.INVALID_HANDLE_VALUE)
                        {
                            procSH = new SafeProcessHandle(processInfo.hProcess, true);
                        }

                        if (processInfo.hThread != (IntPtr)0 && processInfo.hThread != (IntPtr)NativeMethods.INVALID_HANDLE_VALUE)
                        {
                            threadSH.InitialSetHandle(processInfo.hThread);
                        }
                    }

                    if (!retVal)
                    {
                        if (errorCode == NativeMethods.ERROR_BAD_EXE_FORMAT || errorCode == NativeMethods.ERROR_EXE_MACHINE_TYPE_MISMATCH)
                        {
                            throw new Win32Exception(errorCode, "InvalidApplication");
                        }

                        throw new Win32Exception(errorCode);
                    }
                }
            }
            finally
            {
                startupInfo.Dispose();

                if (attributeList != null && !attributeList.IsInvalid)
                {
                    attributeList.Close();
                }

                if (inheritableHandles != null)
                {
                    foreach (var h in inheritableHandles)
                    {
                        if (h != null && !h.IsInvalid)
                        {
                            h.Close();
                        }
                    }
                }
            }
        }

        var ret = false;
        if (procSH != null && !procSH.IsInvalid)
        {
            SetProcessHandle.Invoke(this, new object[] { procSH });
            SetProcessId.Invoke(this, new object[] { processInfo.dwProcessId });
            threadSH.Close();
            ret = true;
        }

        return ret;
    }
}
