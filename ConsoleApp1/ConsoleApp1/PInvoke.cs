using System;
using System.Runtime.InteropServices;

namespace ProcessInjector
{
    /// <summary>
    /// Contains definitions from https://www.pinvoke.net/
    /// </summary>
    public static class PInvoke
    {
        #region For CreateProcess
        /// <summary>
        /// Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
        /// 
        /// <see cref="https://www.pinvoke.net/default.aspx/Structures/StartupInfo.html?diff=y"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        /// <summary>
        /// Contains information about a newly created process and its primary thread. 
        /// 
        /// <see cref="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information"/>\
        /// <seealso cref="https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESS_INFORMATION
        {
            /// <summary>
            /// A handle to the newly created process. 
            /// The handle is used to specify the process in all functions that perform operations on the process object.
            /// </summary>
            public IntPtr hProcess;

            /// <summary>
            /// A handle to the primary thread of the newly created process. 
            /// The handle is used to specify the thread in all functions that perform operations on the thread object.
            /// </summary>
            public IntPtr hThread;


            public int dwProcessId;
            public int dwThreadI;
        }



        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
               string lpApplicationName,
               string lpCommandLine,
               IntPtr lpProcessAttributes,
               IntPtr lpThreadAttributes,
               bool bInheritHandles,
               uint dwCreationFlags,
               IntPtr lpEnvironment,
               string lpCurrentDirectory,
               STARTUPINFO lpStartupInfo,
               PROCESS_INFORMATION lpProcessInformation);
    
        public static class CreationFlags
        {
            public const uint SUSPENDED = 0x4;
        }
        #endregion
    }
}
