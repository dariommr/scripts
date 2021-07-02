# Scripts

## Elasticsearch Indices Reindex Tool: reindex.sh
**USAGE:** `reindex.sh (-a|--all yes | -f|--file /path/file) -s|--server https://elastic_address:port -u|--user user -p|--pass password`
**Note:** The script is not yet complete, I have to develop the `ALL` feature

## Archived Logs Removal Tool: alrt.py

## Windows Event Log converter
It converts windows Event logs from the EventViewer or from an XML file (With a single event) to a one-line JSON string to test it in `ossec-logtest` (or `wazuh-logtest`).

**USAGE:** `Event-Converter.ps1 -LogName Security -EventID 4658`

**EXAMPLE:**
```
{"win":{"system":{"level":"0","systemTime":"2021-07-01T23:19:44.0415260Z","opcode":"0","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","security":"","computer":"DESKTOP-Q1TV95Q","eventID":"4658","channel":"Security","task":"12800","version":"0","correlation":"","providerName":"Microsoft-Windows-Security-Auditing","keywords":"0x8020000000000000","eventRecordID":"174243649","message":"The handle to an object was closed.\\r\\n\\r\\nSubject :\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-2470304919-1303594442-3450856006-1007\\r\\n\\tAccount Name:\\t\\tDario\\r\\n\\tAccount Domain:\\t\\tDESKTOP-Q1TV95Q\\r\\n\\tLogon ID:\\t\\t0x72F85\\r\\n\\r\\nObject:\\r\\n\\tObject Server:\\t\\tSecurity\\r\\n\\tHandle ID:\\t\\t0x694c\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x3004\\r\\n\\tProcess Name:\\t\\tC:\\\\Program Files\\\\Google\\\\Drive\\\\googledrivesync.exe"},"eventData":{"subjectDomainName":"DESKTOP-Q1TV95Q","subjectLogonId":"0x72f85","processId":"0x3004","handleId":"0x694c","subjectUserName":"Dario","objectServer":"Security","subjectUserSid":"S-1-5-21-2470304919-1303594442-3450856006-1007","processName":"C:\\\\Program Files\\\\Google\\\\Drive\\\\googledrivesync.exe"}}}
```

**Configurations needed:**
Configure the Parent rule to link it to JSON decoder and not EventChannel
`/var/ossec/ruleset/rules/0575-win-base_rules.xml`
```
  <rule id="60000" level="2">
    <!-- category>ossec</category -->
    <!-- decoded_as>windows_eventchannel</decoded_as -->
    <decoded_as>json</decoded_as>
    <field name="win.system.providerName">\\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules</description>
  </rule>
```
