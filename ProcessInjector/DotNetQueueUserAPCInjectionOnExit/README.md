# Stealthy Code Injection in a Running .NET Process

# Prologue

For the past few months, I gained interest in understanding more on the Portable Executable(PE) format and Process Injection. [Among the many Process Injection techniques available](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process), I was intrigued by `APC INJECTION`.

# Asynchronous Process Calls (APC)

>Malware can take advantage of Asynchronous Procedure Calls (APC) to force another thread to execute their custom code by attaching it to the APC Queue of the target thread. Each thread has a queue of APCs which are waiting for execution upon the target thread entering alertable state. A thread enters an alertable state if it calls SleepEx, SignalObjectAndWait, MsgWaitForMultipleObjectsEx, WaitForMultipleObjectsEx, or WaitForSingleObjectEx functions. The malware usually looks for any thread that is in an alertable state, and then calls OpenThread and QueueUserAPC to queue an APC to a thread.

The above, taken from `Ashkan Hosseini's` writeup (see credits below), gives a very good overview of APCs and how malwares could possible use them for `Process Injection`.

Basically, 

* Every thread has a queue. 
* You can put a function in this queue. 
* This queue executes asynchronously, meaning when the thread is free and in an alertable state, the function in this queue gets ran FIFO
* For a thread to be in an alertable state, the thread needs to execute one of the following functions
  * [SignalObjectAndWait](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait)
  * [WaitForSingleObjectEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)
  * [WaitForMultipleObjectsEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex)
  * [MsgWaitForMultipleObjectsEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex)
  * [NtTestAlert - Undocumented function, credits to ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert)

# So where are we going with this?

The core of this injection technique is the function [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc). One might think that an Antivirus or an EDR could simply hook into this function and flag whoever uses it. However, this is a frequently used function for `Asynchronous Programming`. So the security solutions might monitor a chain of call from `QueueUserApc` into `ResumeThread` or some other functions like `CreateThread`, `CreateRemoteThread` API calls which are more popular and hence usually more scrutinized by AV/EDR vendors.

What if there exists a way, in the realm of .Net Applications, where most of these calls are done for us by the `Common Language Runtime(CLR)`?

# CLR is Our Friend

When we compile a .Net code, it is compiled into Microsoft Intermediate Language (MSIL) code. This is in the format of a `.exe` or a `.dll`. However these PE files do not contain the machine instructions. A common term for them is `Managed Code`. They are machine independant. As long as you have the right .Net Framework installed, you are good to go.

The  `CLR Loader` loads this `Managed Code` and sends the instructions into the `Just-in-time` compiler which converts the MSIL code at runtime to machine code which is executed by the CPU.

![image](https://user-images.githubusercontent.com/12537739/126520609-c92dfc27-9af6-4604-878e-e471db60e785.png)

Interestingly enough, The image above shows that the CLR ultimately handles the threading support as well. `Threads` in .NET will eventually call one of the alertable methods above, called by the CLR.

A statement in C# such as,

```cs
Thread.Sleep(1000);
```
will eventually be compiled by the JIT and call one of the alertable methods.

The thread is now lying dormant, sleeping. Unless, its APC queue has some function that it needs to execute.

But, we don't even need our target executable to be calling `Thread.Sleep`. 

This amazing [article and research by Dwight Hohnstein](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb), shows that

>Due to the nature of the .NET compiled language runtime, user asynchronous procedure calls (APCs) are processed upon the exit of any .NET assembly without manually triggering an alertable state from managed code.

It shows that the CLR always calls `WaitForMultipleObjectsEx` when ever the program exits!

# What this means for us?

This means we can easily inject our shellcode in the form of MSIL code, into .net executables, without overly using the suspicious chain of API calls, and eventually, when the target program exits, the thread would be set to an alertable state as the CLR calls `WaitForMultipleObjectsEx`, and our shellcode executes.


This inspired me to write a POC to see for myself if it really works.

I am going to omit some code in this examples, so as to make it shorter.

The full source code is in the [repository](https://github.com/wireless90/ProcessInjector.NET/tree/main/ProcessInjector/DotNetQueueUserAPCInjectionOnExit).


# Let's first create our ShellCode

The shellcode is going to be a simple reverse shell written in C#.

Code can be found [here](https://github.com/wireless90/ProcessInjector.NET/tree/main/ProcessInjector/SimpleReverseShell.Net);

I then used [Donut](https://github.com/TheWover/donut) to compile our MSIL binary into a shellcode.

```sh

```

# Credits
* [Ten process injection techniques: A technical survey of common and trending process injection techniques by
Ashkan Hosseini](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

* [The Curious Case of QueueUserAPC by Dwight Hohnstein](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb)

* [Shellcode Execution in a Local Process with QueueUserAPC and NtTestAlert](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert)

* [Donut-PIC Code generator for .NET](https://github.com/TheWover/donut)
