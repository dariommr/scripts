@ECHO OFF

powershell -executionpolicy ByPass ^
    $ar_name = 'disable-account-win.cmd'; ^
    $log_file = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'; ^
    $rollback = $false; ^
    function Write-Log { ^
        param($message); ^
        $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/'+$ar_name+': '; ^
        $log_line += $message; ^
        $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII}; ^
    $alert = Read-Host; ^
    $alert_dict = ConvertFrom-Json $alert; ^
    $alert_id = $alert_dict.parameters.alert.id; ^
    $alert_cmd = $alert_dict.command; ^
    $username = $alert_dict.parameters.alert.data.win.eventData.targetUserName; ^
    if ($alert_cmd -eq 'delete') { ^
            Write-Log 'Rolling back for Alert ID',$alert_id -join ' '; ^
            $rollback = $true} ^
        elseif ($alert_cmd -eq 'add') { ^
            Write-Log 'Starting with Alert ID',$alert_id -join ' '}; ^
    if (!$rollback) { ^
        Disable-LocalUser -Name $username; ^
        Write-Log 'Local user disabled:',$username -join ' '} ^
    else { ^
        Enable-LocalUser -Name $username; ^
        Write-Log 'Local user enabled again:',$username -join ' '}; ^
    Write-Log 'Ended'

:Exit