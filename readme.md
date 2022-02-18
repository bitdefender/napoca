# Bitdefender Napoca Hypervisor
The Bitdefender Napoca project is a lightweight type-1 hypervisor offering a solid foundation for building advanced security-focused functionality by providing control over the resources of a virtualized guest operating system. 
An example of such a project, originally built on top of Napoca, is the [Hypervisor-based Memory Introspection](https://github.com/hvmi/).

# Technology highlights
- As a type-1 (bare-metal) hypervisor, Napoca offers control over - and can improve the security - of the primary operating system, from the start of the boot sequence
- Hardware-assisted virtualization makes the CPU, memory, and all other hardware devices available to the guest operating system, guaranteeing top notch system performance
- Allows interception of memory, MSR, IO, and control register resources based on instruction emulation with customizable behavior
- Rich internal API, including memory management, guest memory management, CPU and virtual CPU management, guest to host communication, inter-processor communication, and advanced debugging
- Can be deployed on UEFI and Legacy platforms by leveraging a provided UEFI loader or the GRUB boot loader
- A userland DLL and a handy sample console application are provided to ease the interaction with the underlying hypervisor

# Main project components
1. Napoca - the actual hypervisor implementation
2. Winguest - Windows user mode (winguestdll) and kernel mode (winguest) components for installing, configuring and interacting with the hypervisor
3. Winguest_sample - user mode sample application built on top of the Winguest code to use as a starting point for developing new tools and showcase how to integrate the API
4. EfiPreloader - a minimal and robust EFI loader application that can ease the adoption of UEFI Secure Boot by acting as a first stage loader to enable a custom chain of trust for the hypervisor (and the OS) boot flow
5. EfiLoader - Napoca boot loader application for UEFI systems

# Building and Running
The project supports only the Microsoft Visual Studio build toolchain under Windows.

## Prerequisites
* Visual Studio 2019
	* Workloads
		* Desktop Development with C++
	* Individual components [recommended to leave already checked options enabled]
		* MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (v14.XX) [version must match the version of an equivalent selected unmitigated lib]
		* C++ ATL for latest v142 build tools with Spectre Mitigations (x86 & x64)
		* Windows 10 SDK (10.0.18362) [1903]
* Windows 10 WDK 10.0.18362 [1903]
* Git
* NASM
	* make sure it is added to the system `PATH` variable
* Powershell 5.0 or later [should already be installed if using Windows 10]
	* Enable powershell scripts: powershell.exe as Admin -> `Set-ExecutionPolicy Unrestricted` -> [A] Yes to All
* Python 3
	* py -3 -m pip install PyYAML
* Doxygen [optional, only required if generating html/latex documentation]

## Build
* Full Build `dacia.sln` using desired platform and configuration options (e.g., x64 - Release)

## Create deployable package
* `./deploy_binaries.ps1 -Platform x64 -Configuration Release -Destination .\install` [customize as needed]

## Install

* Disable secure boot on the target machine (if enabled)
* Copy the 'install' folder obtained previously to the target machine (Following commands assume the folder was copied to `c:\dacia`)
* Run `winguest_sample.exe` as Administrator
	* `drvinstall C:\dacia\install\driver\winguest.inf {8a5531a8-2c02-482e-9b2e-99f8cacecc9d}\BdWinguest`
	* `drvconnect`
	* `setpath 1 C:\dacia\install\hv\`
	* `setpath 2 C:\dacia\install\hv\updates_intro\`
	* `setpath 3 C:\dacia\feedback\`
	* `config enable`
* Reboot

## Validate

* Run `winguest_sample.exe` as Administrator
	* `drvconnect`
	* `queryhv`
	* `help` to see more available commands 

## Debugging

* You can use a debug console over serial by using `config enable serial` in winguest_sample and attaching a serial cable on the onboard COM port. Type `help` to see available commands. Note that you might need to uninstall the Windows serial drivers so that it will not try to use the COM port as well.
* We have a failsafe that will disable the hypervisor after 3 boot attempts without also loading the user mode components. See winguest_sample commands `setfailcnt` and  `resetfailcnt` for more details.

## Credits

The entire Bitdefender Napoca team.

