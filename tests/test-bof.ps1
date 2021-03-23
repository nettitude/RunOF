# Script to test RunOF

# This is designed to be used with the CS-SA bof files

function Test-BOF {
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string] $BofName,
    [Parameter(Mandatory=$false, Position=1)]
    [array] $Params
    )

    "Running BOF $BofName..."

    $x86Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x86\Release\RunBOF.exe'
    $x64Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x64\Release\RunBOF.exe'

    $BofBasePath = "Z:\tools\CS-Situational-Awareness-BOF\SA\"


    & "$x86Exe" "-f" $BofBasePath$BofName'\'$BofName'.x86.o' $Params >> log.txt

    if (-not $?)
    {
        "`tx86: Error..."
    } else {
        "`tx86: OK"
    }

        & "$x64Exe" "-f" $BofBasePath$BofName'\'$BofName'.x64.o' $Params >> log.txt

    if (-not $?)
    {
        "`tx64: Error..."
    } else {
        "`tx64: OK"
    }

}


Test-Bof "cacls" "-Z:C:\\Windows\\system32\\notepad.exe"
Test-Bof "dir" "-Z:C:\\Windows\\system32\\notepad.exe"
Test-Bof "driversigs" 
Test-Bof "env"
Test-Bof "ipconfig"
Test-Bof "ldapsearch" "-Z:*" # don't have a ldap server...
Test-Bof "listdns"
Test-Bof "listmods"
Test-Bof "netstat"
Test-Bof "netview" "-t 30" # This one's a bit slow...
Test-Bof "routeprint"
Test-Bof "nslookup" @("-z:google.com", "-s:1", "-t", "20")
Test-Bof "sc_enum"
Test-Bof "sc_query"
Test-Bof "whoami"
Test-Bof "windowlist"
Test-Bof "resources"
Test-Bof "nslookup" @("-z:nettitude.com", "-s:1", "-t", "20")
Test-Bof "uptime"
Test-Bof "sc_qc" @("-z:", "-z:BthAvctpSvc")
Test-Bof "netuser" @("-Z:jdsnape") 
Test-Bof "sc_qdescription" @("-z:", "-z:BluetoothUserService_74eb1e")
Test-Bof "sc_qfailure" @("-z:", "-z:BluetoothUserService_74eb1e")
Test-Bof "sc_qtriggerinfo" @("-z:", "-z:BluetoothUserService_74eb1e")
Test-Bof "sc_query" @("-z:", "-z:BluetoothUserService_74eb1e")
# NOTE - 32 bit build running on 64 bit windows will only have access to the 32-bit registry (inside Wow6432Node)
Test-Bof "reg_query" @("-i:2", "-z:SOFTWARE\\AiPersist")
Test-Bof "schtasksenum"
Test-Bof "schtasksquery" @("-Z:", "-Z:\Microsoft\Windows\termsrv\RemoteFX\RemoteFXvGPUDisableTask")




# NOT WORKING 


# I think the netgroup ones come from the cna file TODO !!!!
#Test-Bof "netgrouplist"
#Test-Bof "netsession"

# WMI errors
Test-Bof "tasklist"

#Test-Bof "wmi_query"