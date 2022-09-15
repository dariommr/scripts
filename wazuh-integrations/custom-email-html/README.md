# Custom email alerts in HTML
This integration can either read the configurations about email from the `global` section in the `ossec.conf` file (SMTP without authentication) or you can pass custom email configurations in the `integration` block (SMTP with authentication)

## Features
- It sends emails in HTML format
- SMTP with authentication and without authentication (You can use this configuration to connect through a server with authentications such as gmail, outlook, etc.)

## Configuration
Copy the content of the file inside a new file in the following location:
```
/var/ossec/integrations/custom-email-html
```
Change the permissions and ownership:
```
chown root:wazuh /var/ossec/integrations/custom-email-html
chmod 750 /var/ossec/integrations/custom-email-html
```

### SMTP with Authentication:
Configure the integration in ossec.conf
```
  <integration>
    <name>custom-email-html</name>
    <api_key>to@email.com:password</api_key>
    <hook_url>smtp.email.com:port</hook_url>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
```

### SMTP without Authentication:
Configure the email settings on ossec.conf:
```
  <global>
    <smtp_server>smtp.email.com</smtp_server>
    <email_from>sender@email.com:password</email_from>
    <email_to>to@email.com:password</email_to>
  </global>
```
And then configure the integration in the ossec.conf:
```
  <integration>
    <name>custom-email-html</name>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
```
As you can see, in the integration you do not have to specify hook_url or api_key when using the SMTP without authentication from the global section.

