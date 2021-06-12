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

        #region For ZwUnmapViewOfSection 

        /// <summary>
        /// <see cref="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55"/>
        /// </summary>
        public enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0, // The operation completed successfully.
            STATUS_ACCESS_DENIED = 0xC0000022 // A process has requested access to an object but has not been granted those access rights.

        }

        public static class  Offsets
        {
            public const int E_LFANEW = 0x3C;
        }

        /// <summary>
        /// The ZwUnmapViewOfSection routine unmaps a view of a section from the virtual address space of a subject process.
        /// 
        /// <see cref="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection"/>
        /// </summary>
        /// <param name="ProcessHandle">Handle to a process object. You can take this handle from the <see cref="PROCESS_INFORMATION.hProcess"/></param>
        /// <param name="BaseAddress">
        ///     Pointer to the base virtual address of the view to unmap.
        ///     <see cref="https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg"/>
        ///     Although the above is for a pe32, pe64 is slightly different as the imagebase is at 0x0030 and 8 bytes long and not at 0x0034 4 bytes long
        /// </param>
        /// <returns><see cref="NTSTATUS"/></returns>
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS ZwUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);
        #endregion
    }
}
