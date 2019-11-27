<#
.SYNPOSIS
Clean Dridex infection from Windows systems, names is located in hostnames.txt



.EXAMPLE
PS > .\dedri-automatization.ps1

 


.Notes
Author: LIFARS @mwlac
Date: November 17, 2019

.LINK
https://github.com/Lifars/Dridex-Vaccine
#>

$RemoteLogFile = "C$\ProgramData\dedri.log"
$LogFile = ".\dedri-automatization.log"
$HostnameFile = ".\hostnames.txt"
$DedriFile = ".\dedri.ps1"
$RemoteDedriFile = "C:\Dedri.ps1"
$RemoteDedriPath = "c$\Dedri.ps1"
$PsExec = ".\PsExec.exe"

function Out-HostLogFile
{
    param (
    [Parameter(ValueFromPipeline)]
        [Object]$param
    )
     echo $param | Out-File $LogFile -Append
     echo $param | Out-Host
}

echo "Dedri Vaccine Automatization Tool" | Out-HostLogFile
Get-Date | Out-HostLogFile
echo "" | Out-HostLogFile

echo "Running in $(Get-Location)" | Out-HostLogFile
echo "Reading list of hostnames from file $HostnameFile from current directory" | Out-HostLogFile
if (Test-Path -Path $HostnameFile -PathType Leaf)
{
    $Hostnames = Get-Content $HostnameFile
    echo "Read list of $($Hostnames.Length) hostnames" | Out-HostLogFile
    echo "Deploying Dedri Vaccine on remote machines" | Out-HostLogFile
    foreach ($Hostname in $Hostnames)
    {
        if (Test-Path "\\$Hostname\c$")
        {
            echo "    Copy $DedriFile to $Hostname" | Out-HostLogFile
            Copy-Item $DedriFile \\$Hostname\$RemoteDedriPath
            echo "    Executing PsExec with $RemoteDedriFile on $Hostname" | Out-HostLogFile
            Start-Process -WindowStyle Hidden $PsExec -ArgumentList /AcceptEula,\\$Hostname,cmd,/c,"powershell -noninteractive -executionPolicy Bypass -file $RemoteDedriFile" | Out-HostLogFile
        }
        else
        {
            echo "    Warning: $Hostname is not accessible" | Out-HostLogFile
        }
    }

    echo "Waiting 360 seconds for completion of tasks on remote machines..." | Out-HostLogFile
    for ($i = 0; $i -lt 360; $i += 10)
    {
        echo "    ($i)"
        sleep 10
    }

    echo "Collecting Dedri log files from remote machines" | Out-HostLogFile
    New-Item -ItemType Directory -ErrorAction SilentlyContinue ./Logs
    foreach ($Hostname in $Hostnames)
    {
        if (Test-Path "\\$Hostname\c$")
        {
            if (Test-Path "\\$Hostname\$RemoteLogFile")
            {
                echo "    Copy $RemoteLogFile from $Hostname" | Out-HostLogFile
                Copy-Item \\$Hostname\$RemoteLogFile ./Logs/$hostname-dedri.log
                echo "    Remove Dedri Log from $Hostname" | Out-HostLogFile
                Remove-Item \\$Hostname\$RemoteLogFile
            }
            else
            {
                echo "    Warning: $Hostname powershell error" | Out-HostLogFile
            }
            echo "    Remove Dedri from $Hostname" | Out-HostLogFile
            Remove-Item \\$Hostname\$RemoteDedriPath
        }
        else
        {
            echo "    Warning: $Hostname is not accessible" | Out-HostLogFile
        }
    }
    echo "Finished" | Out-HostLogFile
}
else{
    echo "Hostnames file not found, exit" | Out-HostLogFile
}
