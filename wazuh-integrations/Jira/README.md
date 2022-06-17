# Jira Integration

## Rationale
Script that takes alerts from the Wazuh Integratord daemon and creates alerts in the Jira service.

## Wazuh Configuration
Integration block:
```
<integration>
     <name>custom-jira.py</name>
     <hook_url>API_URL</hook_url>
     <api_key>email:token</api_key>
     <alert_format>json</alert_format>
</integration>
```
