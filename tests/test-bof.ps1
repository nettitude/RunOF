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
    [string] $Params
    )

    $x86Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x86\Release\RunBOF.exe'
    $x64Exe = 'Z:\documents\RT\runof\RunOF\RunOF\bin\x64\Release\RunBOF.exe'

    $BofBasePath = "Z:\tools\CS-Situational-Awareness-BOF\SA\"


    & "$x86Exe" "-f" $BofBasePath$BofName'\'$BofName'.x86.o' "$Params"

    if (-not $?)
    {
        "Error running bof..."
    }

        & "$x64Exe" "-f" $BofBasePath$BofName'\'$BofName'.x64.o' "$Params"

    if (-not $?)
    {
        "Error running bof..."
    }

}


#Test-Bof "cacls" "-Z:C:\\Windows\\system32\\notepad.exe"
#Test-Bof "dir" "-Z:C:\\Windows\\system32\\notepad.exe"
#Test-Bof "driversigs" 
Test-Bof "env"
Test-Bof "ipconfig"
#Test-Bof "ldapsearch" "-Z:*"
Test-Bof "listdns"
Test-Bof "listmods"
Test-Bof "netstat"
Test-Bof "netuser" "Administrator"
Test-Bof "netview" "-t -1" # This one's a bit slow...