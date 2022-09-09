# Custom email alerts in HTML
This integration can either read the configurations about email from the `global` section in the `ossec.conf` file (SMTP without authentication) or you can pass custom email configurations in the `integration` block (SMTP with authentication)

## Integrator block configuration
### SMTP Without authentication
```
  <integration>
    <name>custom-email-html</name>
    <level>5</level>
    <alert_format>json</alert_format>
  </integration>
```
This will tell the script to use the email configurations from the `ossec.conf` file.

### SMTP With authentication
```
  <integration>
    <name>custom-email-html</name>
    <api_key>user@gmail.com:app_password</api_key>
    <hook_url>smtp.gmail.com:465</hook_url>
    <level>5</level>
    <alert_format>json</alert_format>
  </integration>
```
You can use this configuration to connect through a server with authentications such as gmail, outlook, etc.