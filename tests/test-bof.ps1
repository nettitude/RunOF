# Script to test RunOF











#$Files = Get-ChildItem -Path Z:\tools\CS-Situational-Awareness-BOF\SA\ -Filter *.x86.o -Recurse -ErrorAction SilentlyContinue -Force

#foreach ($File in $Files) {
 #   & "$x86Exe" "-f" $File.FullName
  #  }

# This is designed to be used with the CS-SA bof files

function Test-BOF {
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string] $BofName,
    [Parameter(Mandatory=$false, Position=1)]
    [array] $Params
    )

    $x86Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x86\Release\RunBOF.exe'
    $x64Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x64\Release\RunBOF.exe'

    $BofBasePath = "Z:\tools\CS-Situational-Awareness-BOF\SA\"


    & "$x86Exe" "-f" $BofBasePath$BofName'\'$BofName'.x86.o' $Params

    if (-not $?)
    {
        "Error running bof..."
    }

       # & "$x64Exe" "-f" $BofBasePath$BofName'\'$BofName'.x64.o' $Params 

    if (-not $?)
    {
        "Error running bof..."
    }

}


#Test-Bof "cacls" "-Z:C:\\Windows\\system32\\notepad.exe"
#Test-Bof "dir" "-Z:C:\\Windows\\system32\\notepad.exe"
#Test-Bof "driversigs" 
#Test-Bof "env"
#Test-Bof "ipconfig"
#Test-Bof "ldapsearch" "-Z:*" # don't have a ldap server...
#Test-Bof "listdns"
#Test-Bof "listmods"
#Test-Bof "netstat"
#Test-Bof "netview" "-t 30" # This one's a bit slow...
#Test-Bof "routeprint"
#Test-Bof "nslookup" @("-z:google.com", "-s:1", "-t", "20")
#Test-Bof "sc_enum"
#Test-Bof "sc_query"
#Test-Bof "whoami"
#Test-Bof "windowlist"
#Test-Bof "resources"
Test-Bof "nslookup" @("-z:nettitude.com", "-s:1", "-t", "20")
Test-Bof "uptime"

# NOT WORKING 
#Test-Bof "netuser" "jdsnape" # DOESN'T WORK? exception 0x6BA !!!!
# Test-Bof "sc_qc" @("-Z:BthAvctpSvc")
#Test-Bof "sc_qdescription" @("-z:BluetoothUserService_74eb1e")

# These ones works in x64 but not in x86 - odd!
#Test-Bof "reg_query" @("-i:2", "-z:SOFTWARE\\AiPersist")
#Test-Bof "schtasksenum"
#Test-Bof "schtasksquery" @("-z:\Microsoft\Windows\termsrv\RemoteFX\RemoteFXvGPUDisableTask")

# I think the netgroup ones come from the cna file TODO !!!!
#Test-Bof "netgrouplist"
#Test-Bof "netsession"

# WMI errors
#Test-Bof "tasklist"
#Test-Bof "wmi_query"