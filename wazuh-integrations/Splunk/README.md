# Splunk integration
Sends alerts to the Splunk API

## Integration block
```
<integration>
  <name>custom-splunk-integration.py</name>
  <hook_url>API_URL</hook_url>>
  <level>3</level>
  <api_key>Splunk:TOKEN</api_key>
  <alert_format>json</alert_format>
</integration>
```