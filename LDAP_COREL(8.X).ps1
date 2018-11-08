#################################################################################################################################################################################################################
#################################################################################################################################################################################################################

$etpath = "C:\Program Files (x86)\Prism Microsystems\EventTracker"
$outputtpath = "C:\Users\jithinr\Desktop\LDAP_COREL\Output"
$credspath = "C:\Users\jithinr\Desktop\LDAP_COREL"
$duration = "-24"
$domain = "GABELLI.LOCAL"

#######################################################################################################################################

Function Invoke-MDBSQLCMD ($mdblocation,$sqlquery){
$dsn = "Provider=Microsoft.Jet.OLEDB.4.0; Data Source=$mdblocation;"
$objConn = New-Object System.Data.OleDb.OleDbConnection $dsn
$objCmd  = New-Object System.Data.OleDb.OleDbCommand $sqlquery,$objConn
$objConn.Open()
$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $objCmd
$dataset = New-Object System.Data.DataSet
[void] $adapter.Fill($dataSet)
$objConn.Close()
$dataSet.Tables | Select-Object -Expand Rows
$dataSet = $null
$adapter = $null
$objCmd  = $null
$objConn = $null
}

$creds = Import-Csv -Path $credspath\creds.csv

Function LDAP-User {
Param ($user)
$path = "LDAP://$domain"
$username = $creds.domainuser
$password =  (New-Object System.Net.NetworkCredential($env:UserName,($creds.domainpassword|ConvertTo-SecureString))).Password
$root = [adsi]::new($path,$username,$password)            
$search = [adsisearcher]$root            
$search.Filter = "(&(objectCategory=person)(objectClass=user)(samaccountname=$user))"                     
$find = (($search.FindOne()).Properties).samaccountname
$find
}

$logprocessdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.LogSearchProcess.dll")
$logparmeterdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.LogSearchParameter.dll")
$datapersist = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.Report.DataPersistance.dll")

#################################################################################################################################################################################################################
#################################################################################################################################################################################################################

$logparmeter01 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter02 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logcerteria = New-Object Prism.LogSearchParameter.LogSearchParameter
$searchconfig = New-Object Prism.LogSearchParameter.SearchConfig
$searchconfig.IsParseTokens = "False"
$logcerteria.FromDate = (get-date).AddHours($duration)
$logcerteria.ToDate = (get-date)
$logcerteria.SystemGroups = "All Windows Systems"
$logcerteria.SystemIncludeType = 1
$logparmeter01.ParameterId = 0
$logparmeter01.Operator = 1
$logparmeter01.ParameterName = "event id"
$logparmeter01.ParameterType = 1
$logparmeter01.SearchValue = "4625"
$logparmeter02.ParameterId = 0
$logparmeter02.Operator = 1
$logparmeter02.ParameterName = "source"
$logparmeter02.ParameterType = 1
$logparmeter02.SearchValue = "Microsoft-Windows-Security-Auditing"
$logcerteria.AdvancedParameter = $logparmeter01
$logcerteria.AdvancedParameter += $logparmeter02
$logticks = (get-date).Ticks
$mdbname1 = "LogonAnalysis_{0}" -f $logticks
$param = new-object Prism.LogSearchParameter.LogSearchParameterContext ("$mdbname1")
$param.Update($logcerteria)
$search = new-object Prism.LogSearchProcess.LogSearchProcessing ("$mdbname1")
$search.StartProcessing(4) | Out-Null

$regex2 = '(?s)Logon Type\:\s+(\d+).*?Account For Which Logon Failed\:.*?Account Name\:\s+(.*?)Account Domain\:\s+(.*?)Failure Information\:.*?Failure Reason\:\s+(.*?)Status\:.*?Caller Process Name\:(.*?)Network Information\:.*?Workstation Name\:\s+(.*?)Source Network Address\:\s+(.*?)Source Port\:\s+(.*?)Detailed Authentication Information\:'
Filter Extract2 {
$_.EventDescription -match $regex2 > $null
[pscustomobject]@{
EventTime = $_.LogTime
HostName = $_.Computer
LogonType = Switch (($Matches[1]).trim())
    {
    2 {"Interactive"}
    3 {"Network"}
    4 {"Batch"}
    5 {"Service"}
    7 {"Unlock"}
    8 {"NetworkCleartext"}
    9 {"NewCredentials"}
    10 {"RemoteInteractive"}
    11 {"CachedInteractive"}
    }     
UserName = (($Matches[2]).trim()) -replace "^.*?\\",""
UserDomain = ($Matches[3]).trim()
FailureReason = ($Matches[4]).trim()
ProcessName = ($Matches[5]).trim()
WorkstationName = ($Matches[6]).trim()
SourceIP = ($Matches[7]).trim()
SourcePort = ($Matches[8]).trim()
}}
$mdblocation1 = "$etpath\Reports\LogSearch\$mdbname1.mdb"
$query1 = Invoke-MDBSQLCMD $mdblocation1 -sqlquery "Select LogTime,Computer,EventDescription from Events" | Extract2
$query1 | Select-Object -Property EventTime,HostName,FailureReason,UserName,UserDomain, @{n='UserStatus';e= {if (LDAP-User -user $_.UserName) {'Valid'} else {'Invalid'}}},LogonType,ProcessName,WorkstationName,SourceIP,SourcePort | export-csv -Path "$outputtpath\Logon_Failure.csv" -NoTypeInformation

#################################################################################################################################################################################################################
#################################################################################################################################################################################################################

