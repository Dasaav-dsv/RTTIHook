# RTTIHook

## A highly customizable header only RTTI analysis and VFT hooking toolset.
RTTIHook is a set of three simple to use C++17 headers, designed for hooking virtual function/method tables (VFTs/VMTs) by locating them through static runtime type information (RTTI) analysis.

## Pros:
### Usage simplicity
Include "VFTHook.h", create an RTTI scanner instance and scan, apply hooks by creating them with "new" and remove them with "delete".
A usage example can be seen in example/dllmain.cpp in the form of an Elden Ring DLL that turns the player character upside down.
### Hook chaining
Hooking a virtual function that has already been hooked simply adds the hook to a chain, without a length limit. 
### Hook compatibility
Any hook placed by RTTIHook will be compatible with any other, even if the underlying assembly is changed. 
Hooks do not need to be directly managed by one context, any combination of threads, DLLs and applications work.
### Custom hooks
RTTIHook supports any kind of custom assembly (provided the modified hook assembly is actually functional)
### Race condition resistance
Placing and removing hooks is designed to be resistant to race conditions, even when two or more different threads, DLLs or applications manage the same virtual function table slot. 
### Fast RTTI scanner and analyzer
The scanner matches specific instruction patterns using custom SIMD search functionality, covering all the .text sections of an executable.
### Header only
Three self-contained (but co-dependent) headers without third party dependencies.

## Limitations:
### Only one instance of a parser and a scanner is supported
For simplicity and intercommunication, PEParser and RTTIScanner use static variables to store some of the key data gotten from analysis.
### Limited support for other hooks
While RTTIHook will work with other hooking toolsets, not all of its features are guaranteed to work.
### x86-64 only
This toolset is designed only with x86-64 in mind, for simplicity (again) and for specialization.
