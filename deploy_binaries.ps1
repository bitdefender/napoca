# This script takes the build output and prepares a package that can be used to install/run Napoca Hypervisor on a PC

#Requires -Version 5.0

Param(
    [string]$Platform = 'x64',                  # Build Platform (Win32 or x64)
    [string]$Configuration = 'Release',         # Build Configuration (Release or Debug)
    [string]$Destination = '.\install'          # The location where the package will be stored
)

class FileLocation
{
    [ValidateNotNullOrEmpty()][string]$Source
    [ValidateNotNullOrEmpty()][string]$Destination
    [ValidateNotNullOrEmpty()][string[]]$FileNames
    
    FileLocation(
    [string]$source,
    [string]$destination,
    [string[]]$fileNames
    )
    {
        $this.Source = $source
        $this.Destination = $destination
        $this.FileNames = $fileNames
    }
}

$locations =@(
#                   Source                                                  Destination                                 Files
[FileLocation]::new(".\bin\napoca\x64\$Configuration",                      "$Destination\hv",                          @('napoca.bin')),
[FileLocation]::new(".\bin\efi_preloader\x64\$Configuration",               "$Destination\hv\efi",                      @('bdhvpreloader.efi')),
[FileLocation]::new(".\bin\efi_loader\x64\$Configuration",                  "$Destination\hv\efi",                      @('bdhvloader.efi')),
[FileLocation]::new(".\bin\winguestdll\$Platform\$Configuration",           "$Destination",                             @('winguestdll.dll')),
[FileLocation]::new(".\bin\winguest\$Platform\$Configuration\winguest",     "$Destination\driver",                      @('WdfCoinstaller01009.dll', 'winguest.cat', 'winguest.cdf', 'winguest.inf', 'winguest.sys')),
[FileLocation]::new(".\bin\winguest_sample\$Platform\$Configuration",       "$Destination",                             @('winguest_sample.exe')),
[FileLocation]::new('.\autogen\cmdlines',                                   "$Destination\hv",                          @('cmdline.txt')),
[FileLocation]::new('.\autogen',                                            "$Destination\hv\efi",                      @('efi_cmdline.txt')),
[FileLocation]::new(".\hvmi\bin\x64\$Configuration",                        "$Destination\hv",                          @('introcore.dll')),
[FileLocation]::new('.\hvmi\cami',                                          "$Destination\hv\updates_intro",            @('intro_live_update.bin')),
[FileLocation]::new('.\hvmi\exceptions',                                    "$Destination\hv\updates_intro",            @('exceptions.bin')),
[FileLocation]::new('.\grub\grub-2.02-for-windows',                         "$Destination\hv\legacy\grub",              @('grub-install.exe')),
[FileLocation]::new('.\grub\grub-2.02-for-windows\i386-pc',                 "$Destination\hv\legacy\grub\i386-pc",      @('*'))
)

################################################################################

Write-Host "Deploying files for $Platform - $Configuration"

# Retrieve GRUB

Write-Host 'Fetching GRUB'

if (-Not (Test-Path -Path '.\grub-2.02-for-windows.zip')) # if the grub archive is found near the script do not redownload
{
    Invoke-WebRequest -Uri 'https://ftp.gnu.org/gnu/grub/grub-2.02-for-windows.zip' -OutFile '.\grub-2.02-for-windows.zip'
}

Expand-Archive -Path '.\grub-2.02-for-windows.zip' -DestinationPath '.\grub' -Force

# Copy files

Write-Host "Copying files to $Destination"

foreach ($location in $locations)
{
    [void](New-Item -Path $location.Destination -ItemType directory -Force)

    foreach ($file in $location.FileNames)
    {
        Write-Progress -Activity 'Copying files' -CurrentOperation "$($location.Source)\$file" -PercentComplete ($locations.IndexOf($location) * 100 / $locations.Count)

        Copy-Item -Path "$($location.Source)\$file" -Destination $location.Destination -Force
    }
}

Write-Progress -Activity 'Copying files' -Completed

Write-Host 'Done'
