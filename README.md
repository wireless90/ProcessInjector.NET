# ProcessInjector.NET
Learning Process Hollowing technique


# TLDR

I want to try to inject a dummy application into notepad++ using the `Process Hollowing` technique.

- [Creating our Victim Process](#creating-our-victim-process)
  * [CreateProcessA Parameters](#createprocessa-parameters)
    + [lpApplicationName](#lpapplicationname)
    + [lpCommandLine](#lpcommandline)

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
This represents the process name that we want to create. Weirdly enough, this can be NULL. In the case where this is NULL, the process name must be the first white space–delimited token in the `lpCommandLine` parameter. We will go ahead and leave this parameter to be NULL and specify our process name at `lpCommandLine` parameter instead.

### lpCommandLine
Since our `lpApplicationName` is NULL, the first white space–delimited token of the command line specifies the process name. If you are using a long file name that contains a space, use quoted strings to indicate where the file name ends and the arguments begin. Furthermore, if we were to ommit our extension for our process, it will auto append `.exe`. Lets proceed to put the full path of `notepad++.exe` but avoid the extension.

```cs
  string notepadPath = @"D:\Program Files\Notepad++\notepad++";
```
