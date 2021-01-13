<#
.SYNPOSIS
Clean Dridex infection from Windows system 



.EXAMPLE
PS > .\dedri.ps1

 


.Notes
Author: LIFARS @mwlac
Date: November 17, 2019

.LINK
https://github.com/Lifars/Dridex-Vaccine
#>


$DedriDir = "C:\ProgramData\Dedri"
$LogFile = "C:\ProgramData\dedri.log"
$ProcHack = "$DedriDir\prochack.exe"
$prochack_base64str = "<PUT BASE64-ENCODED PROCESSHACKER.EXE HERE>"
$procmon_base64str = "<PUT BASE64-ENCODED PROCMON.EXE HERE>"

function Out-HostLogFile
{
    param (
    [Parameter(ValueFromPipeline = $True)]
        [Object]$param
    )
     echo $param | Out-File $LogFile -Append
     echo $param | Out-Host
}

Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    public static class Kernel32 
    {

        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern uint GetThreadId(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern int TerminateThread(IntPtr hThread, uint dwExitCode);
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern int GetLastError();
    }
"@

function Suspend-Thread{
    param (
    [Parameter(Mandatory = $True)]
        [int]$ThreadID
    )

    if (Get-CimInstance win32_thread -filter “handle = $ThreadID”)
    {
        $Error = $False
        $err = 0
        $handle = [Kernel32]::OpenThread([Kernel32+ThreadAccess]::SUSPEND_RESUME, $False, [System.UInt32]$ThreadID)

        if ($handle -ne 0)
        {
            if ([Kernel32]::SuspendThread($handle) -eq 4294967295)
            {
                $err = [Kernel32]::GetLastError()
                $Error = $True
            }
            else
            {
                echo "    Thread $ThreadID suspended" | Out-HostLogFile
            }
            [Kernel32]::CloseHandle($handle)
        }
        else 
        {
                $err = [Kernel32]::GetLastError()
                $Error = $True
        }
        if ($Error)
        {
                echo "    Error $err with native suspending thread" | Out-HostLogFile
                echo "    Trying ProcesHacker tool" | Out-HostLogFile
            
                if ((Test-Path -Path $ProcHack -PathType Leaf) -eq $False)
                {
                    [IO.File]::WriteAllBytes($ProcHack, [Convert]::FromBase64String($prochack_base64str))
                }
                & $ProcHack -c -ctype thread -cobject $ThreadID -caction suspend
                sleep 5
        }
    }
    else
    {
        echo "    Thread $ThreadID doesn't exist" | Out-HostLogFile
    }
}

function Resume-Thread{
    param (
    [Parameter(Mandatory = $True)]
        [int]$ThreadID
    )

    $handle = [Kernel32]::OpenThread([Kernel32+ThreadAccess]::SUSPEND_RESUME, $False, [System.UInt32]$ThreadID)

    if ($handle -ne 0)
    {
        if ([Kernel32]::ResumeThread($handle) -eq 4294967295)
        {
            [Kernel32]::GetLastError()
        }
        else
        {
            echo "Thread $ThreadID resumed"  | Out-HostLogFile
        }
        [Kernel32]::CloseHandle($handle)
    }
    else 
    {
        [Kernel32]::GetLastError()
    }
}

function Terminate-Thread{
    param (
    [Parameter(Mandatory = $True)]
        [int]$ThreadID
    )

    if (Get-CimInstance win32_thread -filter “handle = $ThreadID”)
    {
        $Error = $False
        $err = 0
        $handle = [Kernel32]::OpenThread([Kernel32+ThreadAccess]::TERMINATE, $False, [System.UInt32]$ThreadID)

        if ($handle -ne 0)
        {
            if ([Kernel32]::SuspendThread($handle) -eq 4294967295)
            {
                $err = [Kernel32]::GetLastError()
                $Error = $True
            }
            else
            {
                echo "    Thread $ThreadID terminated" | Out-HostLogFile
            }
            [Kernel32]::CloseHandle($handle)
        }
        else 
        {
                $err = [Kernel32]::GetLastError()
                $Error = $True
        }
        if ($Error)
        {
                echo "    Error $err with native terminating thread" | Out-HostLogFile
                echo "    Trying ProcesHacker tool" | Out-HostLogFile
            
                if ((Test-Path -Path $ProcHack -PathType Leaf) -eq $False)
                {
                    [IO.File]::WriteAllBytes($ProcHack, [Convert]::FromBase64String($prochack_base64str))
                }
                & $ProcHack -c -ctype thread -cobject $ThreadID -caction terminate
                sleep 5
        }
    }
    else
    {
        echo "    Thread $ThreadID doesn't exist" | Out-HostLogFile    
    }
}

function Is-SystemFile
{
    param (
    [Parameter(Mandatory = $True)]
        [System.IO.FileInfo]$File
    )
    return (Test-Path "$env:windir\System32\$($File.Name)" -PathType Leaf) -or (Test-Path "$env:windir\$($File.Name)" -PathType Leaf)
}

function Is-InfectedCommand()
{
    param (
    [Parameter(Mandatory = $True)]
        [String]$Command,
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedDirs
    )

    $IsInfected = $False;
    $ExpandedCommand = [System.Environment]::ExpandEnvironmentVariables($Command)

    foreach($InfectedDir in $InfectedDirs)
    {
        $InfectedDirFullName = $InfectedDir.Fullname
        if (($InfectedDirFullName | Select-String "AppData").Matches.Count -gt 0) #AppData dir
        {
            $AppDataDirIndex = ($InfectedDirFullName | Select-String "AppData").Matches.Index
            $AppDataDir = $InfectedDirFullName.Substring($AppDataDirIndex, $InfectedDirFullName.Length - $AppDataDirIndex)         
            if ($ExpandedCommand -like "*$AppDataDir*")
            {
                $IsInfected = $True
            }
        }
        else #System dir
        {
            if ($ExpandedCommand -like "*$InfectedDirFullName*")
            {
                $IsInfected = $True
            }
        }
    } 

    return $IsInfected
}

function Detect-InfectedDirs
{
    $IsInfected = $False
    $WasInfected = $False
    $InfectedDirs = @()
    $System32SubDirs = Get-ChildItem -Force -Directory "$env:windir\System32"
    $AppDataSubDirs = Get-ChildItem -Force -Directory "C:\Users\*\AppData\Roaming\*"
    $Dirs = @($System32SubDirs) + @($AppDataSubDirs)
    foreach ($Dir in $Dirs)
    {
        $IsInfectedDir = $True
        $IsInfectedDir = $True
        $Files = Get-ChildItem -Force -ErrorAction SilentlyContinue $Dir.FullName
        $Extensions = ($Files | select -Property Extension) | Group-Object -Property Extension
        if ((($Files | measure).Count -le 3) -and (($Extensions | where Name -eq ".exe").Count -eq 1) -and (($Extensions | where Name -eq ".dll").Count -le 1) -and (($Extensions | where Name -ne ".dll" | where Name -NotLike ".x*" | measure).Count -eq 1))
        {
            foreach ($File in $Files)
            {
                if ($IsInfectedDir -and (($File.Extension -eq ".dll") -or ($File.Extension -eq ".exe")))
                {
                    $IsSystemFile = Is-SystemFile($File)
                    $IsInfectedDir = $IsInfectedDir -and $IsSystemFile
                }
                else
                {
                    if ($File.Extension -notlike ".x*")
                    {
                        $IsInfectedDir = $False
                    }
                }
            }
        }
        else
        {
            $IsInfectedDir = $False
        }
        If ($IsInfectedDir)
        {
            $IsInfected = $True
            $InfectedDirs = @($InfectedDirs) + @($Dir)
        }
    }

    return $InfectedDirs
}

function Remove-InfectedDirs
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedDirs
    )

    echo "Removing infected dirs:" | Out-HostLogFile
    foreach ($InfectedDir in $InfectedDirs)
    {
        echo "    $($InfectedDir.FullName)" | Out-HostLogFile
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path $InfectedDir.FullName
    }    
}

function Detect-InfectedTasks
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedDirs
    )

    $ScheduledTasks = schtasks.exe /QUERY /V /FO csv | ConvertFrom-Csv | select -property @{Name="Command";Expression={[System.Environment]::ExpandEnvironmentVariables($_."Task To Run")}}, @{Name="RunAsUser";Expression={$_."Run As User"}}, Taskname
    $System32Tasks = $ScheduledTasks | Where-Object {$_.Command -match "system32.*exe"}
    $AppDataTasks = $ScheduledTasks | Where-Object {$_.Command -match "appdata.*exe"}

    $InfectedTasks = @()
    
    $Tasks = @($System32Tasks) + @($AppDataTasks)
    foreach ($Task in $Tasks)
    {
        $Command = $Task.Command
        if (Is-InfectedCommand $Command $InfectedDirs)
        {
            $InfectedTasks = @($InfectedTasks) + @($Task)        
        }
    }

    return $InfectedTasks
}

function Remove-InfectedTasks
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedTasks
    )

    echo "Removing tasks:" | Out-HostLogFile
    foreach ($InfectedTask in $InfectedTasks)
    {
        echo "    $($InfectedTask.TaskName) -> $($InfectedTask.Command)" | Out-HostLogFile
        schtasks.exe /DELETE /TN $($InfectedTask.TaskName) /F
    }    
}

function Detect-InfectedStartups
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedDirs
    )

    $InfectedStartups = @()

    $Startups=Get-ChildItem -Force "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
    $Shell = New-Object -ComObject WScript.Shell
    foreach ($Startup in $Startups)
    {
        $TargetPath = [System.Environment]::ExpandEnvironmentVariables($shell.CreateShortcut($Startup.Fullname).TargetPath)
        if (Is-InfectedCommand $TargetPath $InfectedDirs){
            $InfectedStartups = @($InfectedStartups) + @($Startup)
        }
    }

    return $InfectedStartups
}

function Remove-InfectedStartups
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedStartups
    )

    echo "Removing startups:" | Out-HostLogFile
    foreach ($InfectedStartup in $InfectedStartup)
    {
        echo "    $($InfectedStartup.FullName)" | Out-HostLogFile
        Remove-Item -Force -ErrorAction SilentlyContinue -Path $InfectedStartup.FullName
    }    
}

function Detect-InfectedAutoruns
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedDirs
    )

    $InfectedAutoruns = @()
    
    $null = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

    $AutorunsKey = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*"
    $HKLM_AutorunsKey = Get-Item "HKLM:$AutorunsKey"
    $HKU_AutorunsKey = Get-Item "HKU:\*\$AutorunsKey"

    $AutorunsKeys = @($HKLM_AutorunsKey) + @($HKU_AutorunsKey)
    foreach ($AutorunsKey in $AutorunsKeys)
    {
        $AutorunsProperties = $AutorunsKey.property
        foreach ($Property in $AutorunsProperties)
        {
            $Command = $AutorunsKey.GetValue($Property)
            if ($Command)
            {
               if (Is-InfectedCommand $Command $InfectedDirs){
                    $InfectedAutoruns = @($InfectedAutoruns) + @(new-object psobject -Property @{RegistryKey=$AutorunsKey;Property=$Property;Value=$Command})
                }
            }
        }
    }

    $null = Remove-PSDrive -Name HKU

    return $InfectedAutoruns
}

function Remove-InfectedAutoruns
{
    param (
    [Parameter(Mandatory = $True)]
        [Object[]]$InfectedAutoruns
    )

    $null = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

    echo "Removing autoruns:" | Out-HostLogFile
    foreach ($InfectedAutorun in $InfectedAutoruns)
    {
        echo "    $($InfectedAutorun.RegistryKey):$($InfectedAutorun.Property)" | Out-HostLogFile
        $PSPath =  $InfectedAutorun.RegistryKey.PSPath
        Remove-ItemProperty -PSPath $PSPath -Name $InfectedAutorun.Property
    }    

    $null = Remove-PSDrive -Name HKU
}

function FindInfectedThread
{
    $config_base64str = "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"

    $ProcMon = "$DedriDir\procmon.exe"
    $ProcMonCfg = "$DedriDir\config.pmc"
    $ProcMonPml = "$DedriDir\procmon.pml"
    $ProcMonCsv = "$DedriDir\procmon.csv"

    if ((Test-Path $DedriDir) -eq $True)
    {
        Remove-Procmon
    }
    
    $null = New-Item -Path "C:\ProgramData" -Name "Dedri" -ItemType "directory"
    [IO.File]::WriteAllBytes($ProcMon, [Convert]::FromBase64String($procmon_base64str))
    [IO.File]::WriteAllBytes($ProcMonCfg, [Convert]::FromBase64String($config_base64str))
    

    $InfectedThread = -1

    #do
    #{
        Remove-Item -ErrorAction SilentlyContinue $ProcMonPml
        Remove-Item -ErrorAction SilentlyContinue $ProcMonCsv
        
        echo "        (ProcMon Tracing running for 70 seconds)" | Out-HostLogFile
        & $ProcMon /AcceptEula /LoadConfig $ProcMonCfg /Minimized /Quiet /Runtime 70 /BackingFile $ProcMonPml
        #Start-Process -FilePath $ProcMon -ArgumentList "/AcceptEula","/LoadConfig","$ProcMonCfg","/Minimized","/Quiet","/Runtime","120","/BackingFile","$ProcMonPml"
        sleep 80
        & $ProcMon /AcceptEula /Terminate
        sleep 10
        
        echo "        (ProcMon convert PML to CSV)" | Out-HostLogFile
        & $ProcMon /AcceptEula /LoadConfig $ProcMonCfg /OpenLog $ProcMonPml /Minimized /Quiet /SaveAs $ProcMonCsv /SaveApplyFilter
        sleep 20
        Stop-Process -Force -ErrorAction SilentlyContinue -Name procmon64
        Stop-Process -Force -ErrorAction SilentlyContinue -Name procmon
        if (Test-Path -Path $ProcMonCsv -PathType Leaf)
        {
            $TIDs = (Get-Content $ProcMonCsv | ConvertFrom-Csv | Where-Object -Property Path -eq "C:\Windows\System32\schtasks.exe" | Where-Object -Property Operation -eq "Process Create" | Where-Object -Property "Process Name" -eq "Explorer.exe").TID | Group-Object
        }
        else
        {
            $TIDs = @()
            echo "    (Detection of injected thread via ProcMon failed)" | Out-HostLogFile
        }
    #} while ($TIDs.Length -le 1)

    if ($TIDs.Length -eq 1)
    {
        $InfectedThread = $TIDs[0].Name
    }

    return $InfectedThread
}

function Prevent-Infection
{
    echo "Prevention:" | Out-HostLogFile
    if ((Test-Path "C:\aaa_TouchMeNot_.txt" -PathType Leaf) -eq $False)
    {
        echo "    BitPaymer Prevention created" | Out-HostLogFile
        $null= New-Item -Path "C:\aaa_TouchMeNot_.txt" -ItemType File
        (Get-Item -Force "C:\aaa_TouchMeNot_.txt").Attributes += "Hidden,ReadOnly"
    }
    else
    {
        echo "    BitPaymer Prevention already exists" | Out-HostLogFile
    }
    <#if ((Test-Path -LiteralPath "\\?\C:\Windows ") -eq $False)
    {
        echo "    Dridex Prevention created" | Out-HostLogFile
        $null = New-Item -Path "\\?\C:\Windows " -ItemType File -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath "\\?\C:\Windows ")
        {
            (Get-Item -Force -LiteralPath "\\?\C:\Windows ").Attributes+="Hidden,ReadOnly"
        }
    }
    else
    {
        echo "    Dridex Prevention already exists" | Out-HostLogFile
    }#>
}

function Remove-Procmon
{
    echo "    (Removing temporary files)" | Out-HostLogFile
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue $DedriDir
}

#### MAIN ####

echo "" | Out-HostLogFile
echo "+---------------+" | Out-HostLogFile
echo "| DEDRI Vaccine |" | Out-HostLogFile
echo "+---------------+" | Out-HostLogFile
echo "" | Out-HostLogFile
echo "by LIFARS @mwlac" | Out-HostLogFile
echo "" | Out-HostLogFile
echo "" | Out-HostLogFile
echo "" | Out-HostLogFile
Get-Date | Out-HostLogFile

echo "    (Running detection of infected thread)" | Out-HostLogFile

$InfectedThread = -1
## For disabling detection of infected thread, just comment the next line
$InfectedThread = FindInfectedThread

echo "Infected Thread:" | Out-HostLogFile
if ($InfectedThread -ge 0)
{
    echo "    $($InfectedThread) in Explorer.exe" | Out-HostLogFile
    echo "Suspending thread $InfectedThread"
    $null = Suspend-Thread $InfectedThread
    sleep 5
}
else
{
    echo "    No Injected Thread detected" | Out-HostLogFile
}

$InfectedDirs = Detect-InfectedDirs
echo "Infected Dirs:" | Out-HostLogFile
foreach ($InfectedDir in $InfectedDirs)
{
    echo "    $($InfectedDir.FullName)" | Out-HostLogFile
}

if ($InfectedDirs.Count -ge 1)
{
    echo "" | Out-HostLogFile

    $InfectedTasks = Detect-InfectedTasks $InfectedDirs
    echo "Infected Tasks:" | Out-HostLogFile
    foreach ($InfectedTask in $InfectedTasks)
    {
        echo "    $($InfectedTask.TaskName) -> $($InfectedTask.Command)" | Out-HostLogFile
    }
    echo "" | Out-HostLogFile

    $InfectedStartups = Detect-InfectedStartups $InfectedDirs
    echo "Infected Startups:" | Out-HostLogFile
    foreach ($InfectedStartup in $InfectedStartups)
    {
        echo "    $($InfectedStartup.FullName)" | Out-HostLogFile
    }
    echo "" | Out-HostLogFile

    $InfectedAutoruns = Detect-InfectedAutoruns $InfectedDirs
    echo "Infected Autoruns:" | Out-HostLogFile
    foreach ($InfectedAutorun in $InfectedAutoruns)
    {
        echo "    $($InfectedAutorun.RegistryKey):$($InfectedAutorun.Property) -> $($InfectedAutorun.Value)" | Out-HostLogFile
    }
    echo "" | Out-HostLogFile

    Remove-InfectedDirs $InfectedDirs
    
    if (@($InfectedTasks).Count -ge 1)
    {
        Remove-InfectedTasks $InfectedTasks
    }
    
    if (@($InfectedStartups).Count -ge 1)
    {
        Remove-InfectedStartups $InfectedStartups
    }

    if (@($InfectedAutoruns).Count -ge 1)
    {
        Remove-InfectedAutoruns $InfectedAutoruns
    }
}
else
{
    echo "    Not detected" | Out-HostLogFile
}

if ($InfectedThread -ge 0)
{
        echo "Terminating thread $InfectedThread"
        $null = Terminate-Thread $InfectedThread
}
    
Remove-ProcMon

Prevent-Infection

Get-Date | Out-HostLogFile
echo "===========================================================" | Out-HostLogFile
