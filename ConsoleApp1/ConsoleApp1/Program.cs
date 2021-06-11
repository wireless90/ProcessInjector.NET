using ProcessInjector;
using System;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            string notepadPath = @"D:\Program Files\Notepad++\notepad++";

            PInvoke.STARTUPINFO startupInfo = new PInvoke.STARTUPINFO();
            PInvoke.PROCESS_INFORMATION processInformation = new PInvoke.PROCESS_INFORMATION();

            bool couldNotCreateProcess = !PInvoke.CreateProcess(
                                                lpApplicationName: null,
                                                lpCommandLine: notepadPath,
                                                lpProcessAttributes: IntPtr.Zero,
                                                lpThreadAttributes: IntPtr.Zero,
                                                bInheritHandles: false,
                                                dwCreationFlags: PInvoke.CreationFlags.SUSPENDED,
                                                lpEnvironment: IntPtr.Zero,
                                                lpCurrentDirectory: null,
                                                lpStartupInfo: startupInfo,
                                                lpProcessInformation: processInformation
                                            );
            if (couldNotCreateProcess)
            {
                Console.WriteLine("Failed to create victim process...");
            }

            Console.WriteLine("Successfully created victim process...");

        }
    }
}
