# ProcessInjector.NET
Learning Process Hollowing technique


# TLDR

I want to try to inject a dummy application into notepad++ using the `Process Hollowing` technique.

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
        Console.WriteLine("Failed to create process...");
    }

    Console.WriteLine("Successfully victim process...");

}
```

![image](https://user-images.githubusercontent.com/12537739/121704357-47d02e00-cb06-11eb-8847-46063bc4c2c2.png)
