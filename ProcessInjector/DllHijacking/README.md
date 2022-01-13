# DLL Hijacking in .NET
![image](https://user-images.githubusercontent.com/12537739/149156168-f2cbc972-d278-4595-ad9b-da1ad07bafcd.png)

A simple DLL file was the catalyst to the [most devastating cyberattack against the United States by nation-state hackers.](https://www.upguard.com/news/u-s-government-data-breach)

This breach demonstrates the formidable potency of DLL hijacking and its ability to dismantle entire organizations with a single infected file.

# What is DLL Hijacking?

>DLL hijacking is a method of injecting malicious code into an application by exploiting the way some Windows applications search and load Dynamic Link Libraries (DLL).

This can be replacing an existing dll that a program uses (easy in .NET) or finding for other ways to hijack the dll search path of the program.

# Objectives

We will be focusing on .NET Framework/Core dlls in this section.

1. Hijacking a .NET Dll directly
2. Hijacking Search Path Using Development Mode
3. Hijacking Search Path Using Probing Mode

# Setup

This project involves a simple set up of a `.Net core console project`. We will then install a nuget package of your choice.

For this example, I have chose a nuget called `ObjectCloner`.

![image](https://user-images.githubusercontent.com/12537739/149158281-53069f25-b46f-4b16-8a51-e7e1bd7bb654.png)

Do take note of the version of the dll used as hijacking requires a dll of the same version (at least for this example).

> Note: For .Net Framework, you can use Binding Redirects to insert a dll of a different version.


We have a simple code that uses the library's `DeepClone` method, which clones our object. Then we print both objects to the screen.
```cs
 class Program
    {
        static void Main(string[] args)
        {
            Person person = new Person("Razali");
            Person clonedPerson = ObjectCloner.ObjectCloner.DeepClone(person);

            Console.WriteLine($"{person.Name}={clonedPerson.Name}");
        }
    }

    public class Person
    {
        public Person(string name)
        {
            Name = name;
        }
        public string Name { get; set; }
    }
```

![image](https://user-images.githubusercontent.com/12537739/149162493-a9da9e8f-b97d-464c-b283-6300f7a5840c.png)

What we are more interested in is the program's dependency on the library `ObjectCloner`. 

Compile the program under release and see the `bin\release` directory.

![image](https://user-images.githubusercontent.com/12537739/149163082-cef9d434-e063-48a6-a733-265e7945ed2c.png)


We notice that there exist a dll called `ObjectCloner.dll`. Our objective is to hijack this dll and insert our malicious code.

# Hijacking a .NET Dll directly

For this section, we will be taking a look at replacing the existing dll with a malicious one. To keep things simple for now, we are going to inject code to simply open up `calc.exe`.

As .NET dlls are only MSIL code and not machine code, we can easily reverse it to get the full source. For example, we can use `ilspy.exe` to open `ObjectCloner.dll` and view the source code.

![image](https://user-images.githubusercontent.com/12537739/149341620-747f5dcf-dc85-4035-9bc2-1f0e721bfdd9.png)

`ILSpy` makes it easy for us to save the reverse source code as a project. Let's save the project as `MaliciousObjectCloner`.

![image](https://user-images.githubusercontent.com/12537739/149341811-131d839a-7a7a-4662-ab97-d0232b0022ea.png)

![image](https://user-images.githubusercontent.com/12537739/149341940-018117a8-63be-4dcd-ae71-6dbb43ef7966.png)

The dll has been successfully reversed and saved as a project. Let's proceed to open the project in visual studio add code to open up `calc.exe`.

I have simply added `Process.Start()` to open up `calc.exe`.

![image](https://user-images.githubusercontent.com/12537739/149342591-4e5506cf-1337-4601-ad23-21cf82501e82.png)

Next, we are going to recompile this project in release version.

![image](https://user-images.githubusercontent.com/12537739/149342725-9aff8fea-b84a-411f-a96f-318e25889b83.png)

![image](https://user-images.githubusercontent.com/12537739/149342027-904b7af8-3b4c-40d3-9201-e3de9b0c48a3.png)

![image](https://user-images.githubusercontent.com/12537739/149342956-a24a8865-2f18-4925-8287-9ed87215aa9a.png)

Once we have our new `ObjectCloner.dll`, we can simply replace the other `ObjectCloner.dll` in our `DLLHijacking` project.

![image](https://user-images.githubusercontent.com/12537739/149343321-06a7aa96-fd46-461c-a617-6b19aae728cf.png)

Now launching `DLLHijacking.exe` executes `ObjectCloner`'s `DeepClone` method which we changed to invoke `calc.exe`.
![image](https://user-images.githubusercontent.com/12537739/149344935-549d1da5-f87b-4459-8c4b-f9ae248f487e.png)


DLL Hijacking success!
# Credits
[What is DLL Hijacking? The Dangerous Windows Exploit](https://www.upguard.com/blog/dll-hijacking)

[Deep-dive into .NET Core primitives: deps.json, runtimeconfig.json, and dll's](https://natemcmaster.com/blog/2017/12/21/netcore-primitives/)
