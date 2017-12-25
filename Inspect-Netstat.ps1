$MAILHOST = "smtp.gmail.com"
$MAILPORT = "587"
$MAILUSER ="username@gmail.com"
$MAILPASS = "SecureString Encrypted Password Here"
$MAILAUTH = New-Object System.Management.Automation.PSCredential -ArgumentList $MAILUSER, $($MAILPASS | ConvertTo-SecureString)

$FROM = "from@gmail.com"
$TO = "to@gmail.com"


$ipexclude = "127.0.0.1|0.0.0.0|192.168.1.160|192.168.1.193|192.168.1.205|::"

$processexclude = @(
    
    "chrome",
    "McsClient",    #Sophos
    "swi_service",   #Sophos
    "powershell_ise",
    "Idle",
    "firefox",
    "iexplore"
)

$connectionstatesinclude = @(

    "ESTABLISHED"
    "CLOSE_WAIT",
    "SYN_SENT",
    "TIME_WAIT",
    "FIN_WAIT_2"
)


function Get-DLLInfo ($procid, $tableid) {

    $ProcExecs = Get-WmiObject -Namespace root\cimv2 -Class CIM_Processexecutable

    $Win32Procs = Get-WmiObject -Namespace root\cimv2 -Class Win32_Process

    $ProcsFromWin32 = $Win32Procs | Where Handle -eq $procid

    $dlls = foreach ($ProcFromWin32 in $ProcsFromWin32) {
    
        $ProcFromWin32InProcs = $ProcExecs | Where Dependent -eq $ProcFromWin32.__PATH

        if ($ProcFromWin32InProcs) {
    
            foreach ($ProcExe in $ProcFromWin32InProcs) {
    
                $ExeFile = [wmi] ”$($ProcExe.Antecedent)”

                    if ($ExeFile.__CLASS -eq 'CIM_DataFile') {

                        Select-Object -InputObject $ExeFile -Property FileName,Extension,Manufacturer,Version <#,CreationDate,InstallDate,LastAccessed,LastModified,Encrypted#> -OutVariable $Executables
                }
            }
        }
    }

    $xml = [xml] ($dlls |  ConvertTo-Html)
    
    if ( $xml.html.body.table.GetType().Name -eq "String" ) { 

       return "" #no dlls

    
    }  else {

        $xml.html.body.table.SetAttribute("class","cssDllTable")
        $xml.html.body.table.SetAttribute("id","dlltable$tableid")

        return  $xml.html.body.InnerXML | Out-String
    }
}


$netstat  = & netstat -ano

$processes = $netstat[4..$netstat.count] | ConvertFrom-String | select p2,p3,p4,p5,p6 | where p4 -notmatch $ipexclude | Where p5 -in $connectionstatesinclude | `
    Select  @{n='PID';e={$_.P6}},
            #@{n='Process';e={$((Get-Process -id $_.P6).ProcessName) + "`n`n<pre>" + (Get-DLLInfo $_.P6) + "</pre>"}},
            @{n='Process';e={$((Get-Process -id $_.P6).ProcessName)}},
            @{n='IP';e={($_.P4 -split ":")[0]}},
            @{n='Host';e={[System.Net.Dns]::GetHostEntry(($_.P4 -split ":")[0]).HostName}},
            @{n='Port';e={($_.P4 -split ":")[1]}},
            @{n='Connection';e={$_.P5}},
            @{n='Owner';e={$ip=$($_.P4 -split ":")[0];(Invoke-RestMethod "http://whois.arin.net/rest/ip/$ip").net.name}},
            @{n='Organization';e={$ip=$($_.P4 -split ":")[0];(Invoke-Restmethod (Invoke-RestMethod "http://whois.arin.net/rest/ip/$ip").net.orgRef.'#text').org.name}},
            @{n='City';e={$ip=$($_.P4 -split ":")[0];(Invoke-Restmethod (Invoke-RestMethod "http://whois.arin.net/rest/ip/$ip").net.orgRef.'#text').org.city}},
            @{n='PostalCode';e={$ip=$($_.P4 -split ":")[0];(Invoke-Restmethod (Invoke-RestMethod "http://whois.arin.net/rest/ip/$ip").net.orgRef.'#text').org.postalCode}},
            @{n='State';e={$ip=$($_.P4 -split ":")[0];(Invoke-Restmethod (Invoke-RestMethod "http://whois.arin.net/rest/ip/$ip").net.orgRef.'#text').org."iso3166-2"}},
            @{n='Path';e={(Get-Process -id $_.P6).Path}}

$unknownprocesses = $processes | Where Process -notin $processexclude

#$unknownprocesses  | FT -AutoSize -Wrap

$css = @"

    h3, h5, th { text-align: center; font-family: Segoe UI }
    table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
    th { font-size: 10px;background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
    td { font-size: 10px; padding: 5px 20px; color: #000; }
    tr { background: #b8d1f3; }
    tr:nth-child(even) { background: #dae5f4; }
    tr:nth-child(odd) { background: #b8d1f3; }

    a.cssClickLink { text-decoration:none;font-family: Arial, Helvetica, sans-serif;font-size: 10px;color: #330000;}
    table.cssDllTable  {display:none;margin: auto;font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
    table.cssDllTable  th {font-size: 10px;background: #330000; color: #fff; max-width: 400px; padding: 5px 10px;}
    table.cssDllTable  td {font-size: 10px;padding: 5px 20px;color: #000;}
    table.cssDllTable  tr {background: #ffb3b3;}
    table.cssDllTable  tr:nth-child(even) {background: #d98c8c; }
    table.cssDllTable  tr:nth-child(odd) {background: #ffe6e6; }

"@

$js = @"

    function toggleTable(dllLinkId,dllTableId) {
  
      var link = document.getElementById(dllLinkId);
  
      var lTable = document.getElementById(dllTableId);
  
      var lText = link.innerHTML; 

      if (lText == '+Show DLLs') { 

        link.innerHTML = '-Hide DLLs'; 
        lTable.style.display = "table"; 

      }
      else { 

        link.innerHTML = '+Show DLLs'; 
         lTable.style.display = "none"; 

      } 
    }

"@


$htmlbody = $unknownprocesses | ConvertTo-Html -Head @("<style>$css</style><script>$js</script>") -Title "Process Table" -PreContent @("<h3>Process Table for $env:COMPUTERNAME</h3>`n<h5>reported on: $(Get-Date -Format "MM/dd/yyyy hh:mm:ss tt")</h5>")

$xmlbody = $htmlbody | ConvertTo-Xml

$xmltext=$xmlbody.Objects.Object.'#text'

for ($i = 9; $i -le $($xmltext.count - 3); $i++) {
    
    $prid = (($xmltext[$i] -split "</td>")[0]) -replace "<tr><td>",""

    $prname = (($xmltext[$i] -split "</td>")[1]) -replace "<td>",""

    $prDLLs = Get-DLLInfo -procid $prid -tableid $i
    
    if ($prDLLs -eq "" ) { #no DLLs
        
        continue
      
    }

    $prDLLs = $("<br/><a class=cssClickLink id=link$i onclick=toggleTable($("'link$i'"),$("'dlltable$i'")); href=#>+Show DLLs</a><br/>") + $prDLLs

    $xmltext[$i] = $xmltext[$i].Insert("<tr><td>".Length + $prid.Length + "</td><td>".Length + $prname.Length, $prDLLs)
}

$tempFile = [System.IO.Path]::GetTempFileName()

$xmltext | Out-String | Out-File "$tempFile.html"

if ($unknownprocesses -ne $null) { 
 
  Send-MailMessage -SmtpServer $MAILHOST -From $FROM -To $TO -Subject "Suspecious connections detected on $env:COMPUTERNAME" -Body ($xmltext | Out-String) -BodyAsHtml -Port $MAILPORT -UseSsl -Credential $MAILAUTH -Attachments @("$tempFile.html")

}

Remove-Item -Path $tempFile
Remove-Item -Path "$tempFile.html"

