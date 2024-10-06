#self elivate
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
#download readme
$sh = New-Object -ComObject WScript.Shell
$target = $sh.CreateShortcut("C:\CyberPatriot\README.url").TargetPath
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("$target","C:\Users\$env:UserName\Desktop\README.html")
$content = [IO.File]::ReadAllText("C:\Users\$env:UserName\Desktop\README.html")
#find and make lists
[Int]$pos1 = $content.IndexOf("<b>Authorized Administrators:</b>")
$tempu = $content.Substring($pos1 + 34)
[Int]$pos2 = $tempu.IndexOf("<h2>Competition Guidelines</h2>")
$readMeUsers = $tempu.Substring(0, $pos2)
#admins lists
[Int]$pos3 = $tempu.IndexOf("<b>Authorized Users:</b>")
$readMeAdmins = $tempu.Substring(0,$pos3)
$theYou = $readMeAdmins.IndexOf("(you)")
$readMeAdmins = $readMeAdmins.Substring(0,$theYou) + $readMeAdmins.Substring($theYou + 5) | Out-File "C:\Users\$env:UserName\Desktop\allowed admin list.txt"
Set-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt" -Value (Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt" | Select-String -Pattern 'Password' -NotMatch | Select-String -Pattern '<' -NotMatch)
$sortedUsers = -split (get-content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt")
Set-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt" -Value(Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt" | Select-String -Pattern 'Description' -NotMatch | Select-String -Pattern '---' -NotMatch | Out-String)
(gc "C:\Users\$env:UserName\Desktop\allowed admin list.txt") | ? {$_.trim() -ne "" } | set-content "C:\Users\$env:UserName\Desktop\allowed admin list.txt"
$b = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt"
@(ForEach ($a in $b) {$a.Replace(' ', '')}) > "C:\Users\$env:UserName\Desktop\allowed admin list.txt"
#actual admins
Get-LocalGroupMember -Group "Administrators" | Select-Object Name| Out-File "C:\Users\$env:UserName\Desktop\current admin list.txt"
$adminList = @()
foreach($line in Get-Content "C:\Users\$env:UserName\Desktop\current admin list.txt") {
    if($line -match "\\"){
        $line = $line.split("\\")[1]
    }

     $adminList += $line
}
Clear-Content "C:\Users\$env:UserName\Desktop\current admin list.txt"
$adminList | Out-File -Append "C:\Users\$env:UserName\Desktop\current admin list.txt"
Set-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt" -Value(Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt" | Select-String -Pattern 'Name' -NotMatch | Select-String -Pattern '---' -NotMatch | Out-String)
(gc "C:\Users\$env:UserName\Desktop\current admin list.txt") | ? {$_.trim() -ne "" } | set-content "C:\Users\$env:UserName\Desktop\current admin list.txt"
$b = Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt"
@(ForEach ($a in $b) {$a.Replace(' ', '')}) > "C:\Users\$env:UserName\Desktop\current admin list.txt"
$adminList = -split (Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt")
Get-LocalUser -Name $adminList | Where {"" -contains $_.Description } |Select-Object Name | Out-File "C:\Users\$env:UserName\Desktop\current admin list.txt"
Set-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt" -Value(Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt" | Select-String -Pattern 'Name' -NotMatch | Select-String -Pattern '---' -NotMatch | Out-String)
(gc "C:\Users\$env:UserName\Desktop\current admin list.txt") | ? {$_.trim() -ne "" } | set-content "C:\Users\$env:UserName\Desktop\current admin list.txt"
$b = Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt"
@(ForEach ($a in $b) {$a.Replace(' ', '')}) > "C:\Users\$env:UserName\Desktop\current admin list.txt"
#remove bad admins
$realAdminsList = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt"
$badAdmins = Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt" | Where-Object {$_ -notin $realAdminsList}
Remove-LocalGroupMember -Group "Administrators" -Member $badAdmins -Confirm
#users
$theYou = $readMeUsers.IndexOf("(you)")
$readMeUsers = $readMeUsers.Substring(0,$theYou) + $readMeUsers.Substring($theYou + 5) | Out-File "C:\Users\$env:UserName\Desktop\allowed user list.txt"
Set-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt" -Value (Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt" | Select-String -Pattern 'Password' -NotMatch | Select-String -Pattern '<' -NotMatch)
$sortedUsers = -split (get-content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt")
Set-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt" -Value ($sortedUsers | Sort-Object)
(gc "C:\Users\$env:UserName\Desktop\allowed user list.txt") | ? {$_.trim() -ne "" } | set-content "C:\Users\$env:UserName\Desktop\allowed user list.txt"
$b = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt"
@(ForEach ($a in $b) {$a.Replace(' ', '')}) > "C:\Users\$env:UserName\Desktop\allowed user list.txt"
#get actual users
$userlist = Get-LocalUser -Name * | Where {"" -contains $_.Description } |Select-Object Name, Description | Out-File "C:\Users\$env:UserName\Desktop\current user list.txt"
Set-Content -Path "C:\Users\$env:UserName\Desktop\current user list.txt" -Value(Get-Content -Path "C:\Users\$env:UserName\Desktop\current user list.txt" | Select-String -Pattern 'Description' -NotMatch | Select-String -Pattern '---' -NotMatch | Out-String)
(gc "C:\Users\$env:UserName\Desktop\current user list.txt") | ? {$_.trim() -ne "" } | set-content "C:\Users\$env:UserName\Desktop\current user list.txt"
$b = Get-Content -Path "C:\Users\$env:UserName\Desktop\current user list.txt"
@(ForEach ($a in $b) {$a.Replace(' ', '')}) > "C:\Users\$env:UserName\Desktop\current user list.txt"
#remove bad users
$allowedList = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt"
$badUsers = Get-Content -Path "C:\Users\$env:UserName\Desktop\current user list.txt" | Where-Object {$_ -notin $allowedList}
Write-Output "Try not do disable any otherwise specified users"
$removeUsers = -split $badUsers
Disable-LocalUser -Name $removeUsers -Confirm
#missing users
$allowedList = Get-Content -Path "C:\Users\$env:UserName\Desktop\current user list.txt"
$addUsers = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed user list.txt" | Where-Object {$_ -notin $allowedList}
$creatingUsers = -split $addUsers
foreach($LINE in $addUsers)
    {
        $creatingUsers="$($LINE)"
        $setPassword = ConvertTo-SecureString "Huskey123!" -AsPlainText -Force
        New-LocalUser -Name $creatingUsers -Password $setPassword -FullName $creatingUsers -Confirm
    }
#give admin to users
$currentAdminsList = Get-Content -Path "C:\Users\$env:UserName\Desktop\current admin list.txt"
$newAdminList = Get-Content -Path "C:\Users\$env:UserName\Desktop\allowed admin list.txt" | Where-Object {$_ -notin $currentAdminsList}
Add-LocalGroupMember -Group "Administrators" -Member $newAdminList -Confirm
}
Powershell
