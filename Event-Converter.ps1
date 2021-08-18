<#
.Description
This Script is intended to be use to evaluate Events from EventChannel directly in wazuh-logtest

.PARAMETER LogName
EventChannel Name, such as Application, Security, System, etc.

.PARAMETER EventID
The EventID must be specified with the LogName

.PARAMETER RecordID
Optional parameter if you need to collect a specific event

.PARAMETER FilePath
Specify the Path of the file with a single XML event. If this parameter is specified, the LogName and EventID are no needed

.LINK
Wazuh-Logtest: https://documentation.wazuh.com/current/development/wazuh-logtest.html
Collect Windows Logs: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-to-collect-wlogs.html
#> 
#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'EventLog')]
param (
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'EventLog',
        HelpMessage = 'Enter the Log Name (Application/Security, etc)'
        )][string]$LogName,
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'EventLog',
        HelpMessage = 'Enter the EventID'
        )][string]$EventID,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'EventLog',
        HelpMessage = 'Enter the RecordID if you need a specific event'
        )][string]$RecordID,
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'XMLFile',
        HelpMessage = 'Enter the Path to the XML File'
        )][string]$FilePath
)
#$LogName = ("Security").ToLower()
#$EventID = "4658"
#$RecordID = "43094"
#$FilePath = ".\event.xml"

function ToLogtest($xml_evt) {
    $nodes = $xml_evt.GetElementsByTagName("System")
    $json_evt = @{}
    $json_evt['win'] = @{}
    $json_evt['win']['system'] = @{}
    foreach ($node in $nodes.ChildNodes) {
        if (!($node.HasAttributes)) {
            $json_evt['win']['system'].Add(($node.LocalName).substring(0,1).tolower()+($node.LocalName).substring(1), $xml_evt.Event.System.$($node.LocalName))
        }
        else {
            if ($node.LocalName -eq "Provider") {
                $json_evt['win']['system'].Add("providerName", $xml_evt.Event.System.Provider.Name)
                $json_evt['win']['system'].Add("providerGuid", $xml_evt.Event.System.Provider.Guid)
            }
            if ($node.LocalName -eq "TimeCreated") {
                $json_evt['win']['system'].Add("systemTime", $xml_evt.Event.System.TimeCreated.SystemTime)
            }
        }
    }
    $nodes = $xml_evt.GetElementsByTagName("EventData").Data
    $json_evt['win']['eventData'] = @{}
    if ($nodes.Name) {
        foreach ($node in $nodes) {
            $json_evt['win']['eventData'].Add(($node.Name).substring(0,1).tolower()+($node.Name).substring(1), $node.InnerText)
        }
    }
    else {
        [string]$data = ($xml_evt.GetElementsByTagName("Data")).InnerText
        $json_evt['win']['eventData'].Add("data", $data)
    }
    $bin = ($xml_evt.GetElementsByTagName("Binary")).InnerText
    if ($bin) {
        $json_evt['win']['eventData'].Add("binary", $bin)
    }
    return $json_evt
}

if ($FilePath) {
    $in_file = Get-Content $FilePath
    $ln_num = ($in_file | Select-String -Pattern "Event Xml:").LineNumber
    [xml]$xml_ini = $in_file[$ln_num..$in_file.Count]
    
    $sev_arr = ($in_file | Select-String -Pattern "Level:") -Split(":")
    $sev = $sev_arr[1].Trim()
    $ln_from = ($in_file | Select-String -Pattern "Description:").LineNumber
    $msg = (($in_file[$ln_from..($ln_num-1)]) | Out-String)
}
else {
    if ($RecordID) {
        $evt = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventID} | Where-Object {$_.RecordId -eq $RecordID}
        [xml]$xml_ini = ($evt).ToXML()
    }
    else {
        $evt = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventID} -MaxEvents 1
        [xml]$xml_ini = ($evt).ToXML()
    }
    $msg = $evt.Message
    $sev = $evt.LevelDisplayName
}

$json_fnl = ToLogtest($xml_ini)
$json_fnl['win']['system'].Add('message',$msg)
$json_fnl['win']['system'].Add('severityValue',$sev.ToUpper())


$json_fnl | ConvertTo-Json -Depth 10 -Compress
