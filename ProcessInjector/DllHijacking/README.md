﻿# DLL Hijacking in .NET
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


# Credits
[What is DLL Hijacking? The Dangerous Windows Exploit](https://www.upguard.com/blog/dll-hijacking)