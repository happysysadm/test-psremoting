function Test-PSRemoting
{
<#
.Synopsis
The Test-PSRemoting function tests whether the WinRM service is listenig and able to accept connections on a local or remote computer
.EXAMPLE
Test-PSRemoting -cred (get-credential domain\admin) -ComputerName srv01 -Ping
.EXAMPLE
$cred = get-credential
Test-PSRemoting -cred $cred -ComputerName srv01 -Resolve
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName srv01 -TCPCheck
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName srv01 -DCOM
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName srv01 -Negotiate
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName srv01 -Kerberos
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName srv01 -Ping -Resolve -TCPCheck -DCOM -Negotiate -Kerberos
.EXAMPLE
'srv01','srv02' | % { Test-PSRemoting -cred $cred -ComputerName $_ -Kerberos } | Format-Table *name,*kerberos* -AutoSize
.EXAMPLE
'srv01','srv02' | % { Test-PSRemoting -cred $cred -ComputerName $_ -Ping -Resolve -TCPCheck -DCOM -Negotiate -Kerberos } | Format-Table * -AutoSize
.EXAMPLE
Test-PSRemoting -cred $cred -ComputerName 'srv01','srv02' -Ping -Kerberos | Format-Table *name,ping,*kerberos* -AutoSize
.EXAMPLE
$Report = Start-RSJob -Throttle 20 -Verbose -InputObject ((Get-ADComputer -server dc01 -filter {(name -notlike 'win7*') -AND (OperatingSystem -Like "*Server*")} -searchbase "OU=SRV,DC=Domain,DC=Com").name) -FunctionsToLoad Test-PSRemoting -ScriptBlock {Test-PSRemoting $_ -Ping -Kerberos -Credential $using:cred -Verbose} | Wait-RSJob -Verbose -ShowProgress | Receive-RSJob -Verbose
$Report | ? Remoting_Kerberos -eq 'ok' | convertto-csv -Delimiter ',' -NoTypeInformation | out-file C:\winrm-after-gpo.csv
$Report | ? remoting_kerberos -eq 'nok'  | ? os -notmatch "2000|2003" | format-table * -autosize
.EXAMPLE
$Servers = ((New-Object -typename ADSISearcher -ArgumentList @([ADSI]"LDAP://domain.com/dc=domain,dc=com","(&(&(sAMAccountType=805306369)(objectCategory=computer)(operatingSystem=*Server*)))")).FindAll()).properties.name
$Report = Start-RSJob -Throttle 20 -Verbose -InputObject $Servers -FunctionsToLoad Test-PSRemoting -ScriptBlock {Test-PSRemoting -Ping -Resolve -TCPCheck -DCOM -Negotiate -Kerberos $_ -Credential $using:cred -Verbose} | Wait-RSJob -Verbose -ShowProgress | Receive-RSJob -Verbose
$Report | ? ping -eq 'ok' | format-table * -AutoSize
.NOTES
happysysadm.com
@sysadm2010
#>
    [CmdletBinding()]
    Param
    (
        # List of computers
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('Name')] 
        [string[]]$ComputerName,
 
        # Specifies a user account that has permission to perform this action
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [switch]$Ping,
        [switch]$Resolve,
        [switch]$TCPCheck,
        [switch]$DCOM,
        [switch]$Negotiate,
        [switch]$Kerberos 
    )
 
    Begin
    {
    Write-Verbose "$(Get-Date) - Started."
    $AllResults = @()
    }
    Process
    {
    foreach($Computer in $ComputerName) {
        write-verbose "$(Get-Date) - Working on $Computer"
        $Result = $Null
        $Result = [PSCustomObject]@{
            PSComputerName=$Computer
            IPADDRESS=''
            DOMAIN=''
            OS=''
            DNS=''
            Ping=''
            DCOM=''
            HTTP_5985=''
            HTTPS_5986=''
            WSMAN_NTLM_80=''
            WSMAN_NTLM=''
            Remoting_NTLM=''
            WSMAN_Kerberos_80=''
            WSMAN_Kerberos=''
            Remoting_Kerberos=''
            TimeStamp=Get-Date -f s}
        if($ping){
            Write-Verbose "$(Get-Date) - Sending ping to $Computer"
            try {
                if ((new-object System.Net.NetworkInformation.Ping).send($Computer,100).status -ne "Success") {
                    $Result.Ping = 'NOK' }
                else {
                    $Result.Ping = 'OK' }
                }
            catch {
                $Result.Ping = 'NOK' }
            }
        if($Resolve){
            write-verbose "$(Get-Date) - Resolving server name $Computer"
            try {
                $IP = (Resolve-DnsName -Name $Computer -Type A -ErrorAction Stop)[0].ipaddress 
                $Result.DNS = 'OK'
                $Result.IPADDRESS = $IP }
            catch{
                $Result.DNS = 'NOK' }
            }
        if($TCPCheck){
            Write-Verbose "$(Get-Date) - Trying to connect to $Computer on TCP port 5985"
            $socket = new-object Net.Sockets.TcpClient
            $connect = $socket.BeginConnect($Computer, 5985, $null, $null)
            $NoTimeOut = $connect.AsyncWaitHandle.WaitOne(100, $false)
            if ($NoTimeOut) {
                $socket.EndConnect($connect) | Out-Null
                $Result.http_5985 = 'OK'               
            }
            else {
                $Result.http_5985 = 'NOK'
            }
            Write-Verbose "$(Get-Date) - Trying to connect to $Computer on TCP port 5986"
            $socket = new-object Net.Sockets.TcpClient
            $connect = $socket.BeginConnect($Computer, 5986, $null, $null)
            $NoTimeOut = $connect.AsyncWaitHandle.WaitOne(100, $false)
            if ($NoTimeOut) {
                $socket.EndConnect($connect) | Out-Null
                $Result.https_5986 = 'OK'               
            }
            else {
                $Result.https_5986 = 'NOK'
            }
        }
        if($DCOM){
            Write-Verbose "$(Get-Date) - Trying to connect to $Computer with DCOM to retrieve Domain name and Operating System"
            try {
                $SessionOp = New-CimSessionOption –Protocol DCOM
                $CimSession = New-CimSession -ComputerName $Computer -Credential $Credential `
                    -SessionOption $SessionOp -Name $Computer -OperationTimeoutSec 1 -ErrorAction Stop
                $Result.Dcom = 'OK'
                $Result.DOMAIN = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession `
                        -ErrorAction SilentlyContinue).domain
                $Result.OS = (Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession `
                        -ErrorAction SilentlyContinue).caption
                Remove-CimSession -CimSession $CimSession }
            catch {
                $Result.Dcom = 'NOK'
                $Result.DOMAIN = 'NA'
                $Result.OS = 'NA'} 
                }
        if($Negotiate){
            Write-Verbose "$(Get-Date) - Testing WSMAN with authentication negotiation to $Computer"
            try {
                Test-WSMan $Computer -Authentication Negotiate -ErrorAction Stop -Credential $Credential | Out-Null
                $Result.WSMAN_NTLM = 'OK' }
            catch {
                Write-Verbose "$(Get-Date) - WSMAN with authentication negotiation failed $Computer"
                write-verbose $error[0]
                $Result.WSMAN_NTLM = 'NOK' }
            Write-Verbose "$(Get-Date) - Testing WSMAN with authentication negotiation to $Computer on port 80 (for windows 2003)"
            try {
                Test-WSMan $Computer -Authentication Negotiate -ErrorAction Stop -Credential $Credential -Port 80 | Out-Null
                $Result.WSMAN_NTLM_80 = 'OK' }
            catch {
                Write-Verbose "$(Get-Date) - WSMAN with authentication negotiation failed $Computer on port 80 (for windows 2003)"
                write-verbose $error[0]
                $Result.WSMAN_NTLM_80 = 'NOK' }
            Write-Verbose "$(Get-Date) - Trying remote PowerShell command to $Computer with authentication negotiation"
            $job = Invoke-Command $Computer -scriptblock { Get-Service | Out-Null } -Authentication Negotiate -ErrorAction Stop -AsJob -Credential $Credential
            Wait-Job $job -Timeout 2 -ErrorAction stop | Out-Null
            if($job.state -ne "Completed") {
                write-verbose $error[0]
                $Result.Remoting_NTLM = 'NOK' }
            else{
                $Result.Remoting_NTLM = 'OK' }
            }
        if($Kerberos){
            Write-Verbose "$(Get-Date) - Testing WSMAN with Kerberos authentication to $Computer"
            try {
                Test-WSMan $Computer -Authentication Kerberos -ErrorAction Stop -Credential $Credential | Out-Null
                $Result.WSMAN_Kerberos = 'OK' }
            catch {
                Write-Verbose "$(Get-Date) - WSMAN with Kerberos authentication failed $Computer"
                Write-Verbose $error[0]
                $Result.WSMAN_Kerberos = 'NOK' }
            Write-Verbose "$(Get-Date) - Testing WSMAN with Kerberos authentication to $Computer on port 80 (for windows 2003)"
            try {
                Test-WSMan $Computer -Authentication Kerberos -ErrorAction Stop -Credential $Credential -Port 80  | Out-Null
                $Result.WSMAN_Kerberos_80 = 'OK' }
            catch {
                Write-Verbose "$(Get-Date) - WSMAN with Kerberos authentication failed $Computer on port 80 (for windows 2003)"
                Write-Verbose $error[0]
                $Result.WSMAN_Kerberos_80 = 'NOK' }
            Write-Verbose "$(Get-Date) - Trying remote PowerShell command to $Computer with Kerberos authentication"
            $job = Invoke-Command $Computer -scriptblock { Get-Service | Out-Null } -ErrorAction Stop -AsJob -Credential $Credential
            Wait-Job $job -Timeout 2 -ErrorAction stop | Out-Null
            if($job.state -ne "Completed") {
                Write-Verbose $error[0]
                $Result.Remoting_Kerberos = 'NOK' }
            else{
                $Result.Remoting_Kerberos = 'OK' }
            }
        $AllResults += $Result
        }
    }
    End
    {
    Write-Verbose "$(Get-Date) - Done. Printing results to screen..."
    $AllResults
    }
}
