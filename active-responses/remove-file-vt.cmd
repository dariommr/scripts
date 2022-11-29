@ECHO OFF

powershell -executionpolicy ByPass ^
    $log_file = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'; ^
    $alert = Read-Host; ^
    $alert_dict = ConvertFrom-Json $alert; ^
    $alert_id = $alert_dict.parameters.alert.id; ^
    $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: Starting with Alert ID '+$alert_id; ^
    $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII; ^
    $filename = $alert_dict.parameters.alert.data.virustotal.source.file; ^
    write-host $filename; ^
    if ($alert_dict.parameters.alert.data.integration -eq 'virustotal') { ^
        Remove-Item -Path $filename -ErrorVariable result -ErrorAction SilentlyContinue; ^
        $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: '; ^
        if ($result.Count -eq 0) {$log_line += $filename+' deleted'} else {$log_line += 'Unable to delete. Reason: '+$result[0].CategoryInfo.Reason}; ^
        $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII} ^
    else { ^
        $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: Not a VirusTotal Alert: '+$alert}; ^
    $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: Ended'; ^
    $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII

:Exit