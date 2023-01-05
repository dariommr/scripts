@ECHO OFF

powershell -executionpolicy ByPass ^
    $allowedHosts = '<WAZUH_MANAGER_IP>', '<ANOTHER_IP>'; ^
    $def_gate = (Get-NetRoute ^| where {$_.DestinationPrefix -eq '0.0.0.0/0'}).NextHop; ^
    $allowedHosts += $def_gate; ^
    $user_msg = 'El equipo ha entrado en modo contencion y ha sido aislado. Favor de comunicarse con el administrador'; ^
    $log_file = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'; ^
    $ar_name = 'win-isolation'; ^
    $rollback = $false; ^
    function Write-Log { ^
        param($message); ^
        $log_line = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')+' active-response/bin/'+$ar_name+': '; ^
        $log_line += $message; ^
        $log_line ^| Out-File -FilePath $log_file -Append -Encoding ASCII}; ^
    $in_string = Read-Host; ^
    $alert_dict = ConvertFrom-Json $in_string; ^
    $alert_id = $alert_dict.parameters.alert.id; ^
    $alert_cmd = $alert_dict.parameters.extra_args[0]; ^
    if ($alert_cmd -eq 'delete') { ^
        Write-Log 'Rolling back for Alert ID',$alert_id -join ' '; ^
        $rollback = $true} ^
    elseif ($alert_cmd -eq 'add') { ^
        Write-Log 'Starting with Alert ID',$alert_id -join ' '} ^
    else { ^
        Write-Log 'Incorrect command for Alert ID',$alert_id -join ' '; ^
        Exit}; ^
    if (!$rollback) { ^
        $WindowsFirewall = Get-NetFirewallProfile ^| Where-Object { $_.Enabled -ne $false }; ^
        if ($WindowsFirewall) { ^
            Write-Log 'Windows Firewall is not enabled. Enabling for extra isolation'; ^
            $WindowsFirewall ^| Set-NetFirewallProfile -Enabled:True}; ^
        $ruleName = 'Wazuh-Isolation: Outbound'; ^
        $ExistingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; ^
        if ($ExistingRule) { ^
            Get-NetFirewallRule -Direction Outbound ^| Set-NetFirewallRule -Enabled:False; ^
            $null = Set-NetFirewallRule -Direction Outbound -Enabpowersled:True -Action Allow -RemoteAddress $allowedHosts -DisplayName $ruleName; ^
            Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultOutboundAction Block} ^
        else { ^
            Get-NetFirewallRule -Direction Outbound ^| Set-NetFirewallRule -Enabled:False; ^
            $null = New-NetFirewallRule -Direction Outbound -Enabled:True -Action Allow -RemoteAddress $allowedHosts -DisplayName $ruleName; ^
            Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultOutboundAction Block}; ^
        $ruleName = 'Wazuh-Isolation: Inbound'; ^
        $ExistingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; ^
        if ($ExistingRule) { ^
            Get-NetFirewallRule -Direction Inbound ^| Set-NetFirewallRule -Enabled:False; ^
            $null = Set-NetFirewallRule -Direction Inbound -Enabled:True -Action Allow -RemoteAddress $allowedHosts -DisplayName $ruleName; ^
            Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultInboundAction Block} ^
        else { ^
            Get-NetFirewallRule -Direction Inbound ^| Set-NetFirewallRule -Enabled:False; ^
            $null = New-NetFirewallRule -Direction Inbound -Enabled:True -Action Allow -RemoteAddress $allowedHosts -DisplayName $ruleName; ^
            Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultInboundAction Block}; ^
        Write-Log 'Firewall Isolation rules created'; ^
        Stop-Service -name 'LanmanWorkstation' -Force; ^
        Get-Service -name 'LanmanWorkstation' ^| Set-Service -StartupType Disabled; ^
        Stop-Service -name 'LanmanServer' -Force; ^
        Get-Service -name 'LanmanServer' ^| Set-Service -StartupType Disabled; ^
        msg * $user_msg; ^
        Write-Log 'Services Workstation and Server Stopped and Disabled'} ^
    else { ^
        $ruleName = 'Wazuh-Isolation: Outbound'; ^
        Get-NetFirewallRule -Direction Outbound ^| Set-NetFirewallRule -Enabled:True; ^
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; ^
        Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultOutboundAction Allow; ^
        $ruleName = 'Wazuh-Isolation: Inbound'; ^
        Get-NetFirewallRule -Direction Inbound ^| Set-NetFirewallRule -Enabled:True; ^
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; ^
        Get-NetFirewallProfile ^| Set-NetFirewallProfile -DefaultInboundAction Allow; ^
        Write-Log 'Firewall Isolation rules deleted'; ^
        Get-Service -name 'LanmanWorkstation' ^| Set-Service -StartupType Automatic; ^
        Start-Service -name 'LanmanWorkstation'; ^
        Get-Service -name 'LanmanServer' ^| Set-Service -StartupType Automatic; ^
        Start-Service -name 'LanmanServer'; ^
        Write-Log 'Services Workstation and Server Enabled and Started'}; ^
    Write-Log 'Ended'

:Exit