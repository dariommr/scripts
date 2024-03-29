@ECHO OFF

powershell -executionpolicy ByPass ^
    $log_file = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'; ^
    $alert = Read-Host; ^
    $alert_dict = ConvertFrom-Json $alert; ^
    $alert_id = $alert_dict.parameters.alert.id; ^
    $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: Starting with Alert ID '+$alert_id; ^
    $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII; ^
    $filename = $alert_dict.parameters.alert.syscheck.path; ^
    $filesize = $alert_dict.parameters.alert.syscheck.size_after; ^
    $filehash = $alert_dict.parameters.alert.syscheck.md5_after; ^
    $filesmatching = Get-ChildItem -Path $(Split-Path $filename) -file ^| Where-Object {$_.Length -eq $filesize}; ^
    ForEach ($file in $filesmatching) { ^
        $hash = Get-FileHash -Algorithm MD5 -Path $file.FullName; ^
        if ($hash.Hash -eq $filehash) { ^
            Remove-Item -Path $hash.Path -ErrorVariable result -ErrorAction SilentlyContinue; ^
            $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: '; ^
            if ($result.Count -eq 0) {$log_line += $hash.Path+' deleted'} else {$log_line += 'Unable to delete. Reason: '+$result[0].CategoryInfo.Reason}} ^
            $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII}; ^
    $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/remove-file-fim.cmd: Ended'; ^
    $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII

:Exit