using System;
using System.Runtime.InteropServices;

namespace ProcessInjector
{
    /// <summary>
    /// Contains definitions from https://www.pinvoke.net/
    /// </summary>
    public static class PInvoke
    {
        /// <summary>
        /// <see cref="https://www.pinvoke.net/default.aspx/Structures/StartupInfo.html?diff=y"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
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
    }
}
