import os, sys
import logging
import smtplib, ssl
import email
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import xml.etree.ElementTree as ET

################################################## Global variables ##################################################

wazuh_conf = "/var/ossec/etc/ossec.conf"
logo = "https://wazuh.com/assets/wazuh-signature.png"

log_file = "/var/ossec/logs/integrations.log"
DEBUG = False

################################################## Common functions ##################################################

# Enables logging and configure it
def set_logger(name, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)
    formatter = logging.Formatter(format)
    if DEBUG:
        logging.getLogger('').setLevel(logging.DEBUG)
    else:
        logging.getLogger('').setLevel(logging.INFO)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    logging.getLogger('').addHandler(streamHandler)
    
    if logfile:
        fileHandler = logging.FileHandler(logfile)
        fileHandler.setFormatter(formatter)
        logging.getLogger('').addHandler(fileHandler)

# Function to read the global tag from the ossec.conf file and extract email configurations.
def read_conf(conf_loc):
    conf_file = open(conf_loc, "r")
    conf_data = "<xml_config>\n"+ conf_file.read() +"</xml_config>"
    xml_data = ET.fromstring(conf_data)
    global_conf = xml_data[0].findall('global')
    try:
        email_conf = {
            "enabled": global_conf[0].find('email_notification').text,
            "server": global_conf[0].find('smtp_server').text,
            "from": global_conf[0].find('email_from').text
        }
        tos = global_conf[0].findall('email_to')
        tmp_to = ""
        for to in tos:
            tmp_to += to.text+","
        email_conf["to"] = tmp_to
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error reading the ossec.conf file.: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return email_conf

# Creates an HTML table from an input dictionary
def create_table(in_dict):
    str_table = '<table style="text-align: left; width: 676px; "border="1" cellpadding="2" cellspacing="2">\n'
    str_table = str_table+"  <tbody>\n"
    try:
        for k,v in in_dict.items():
            if isinstance(v,dict):
                for sk, sv in v.items():
                    field_name = k.title()+"."+sk.title()
                    str_table = str_table+'    <tr height="20px">\n'
                    str_table = str_table+'      <td style="width: 140px;">'+field_name+'</td>\n'
                    str_table = str_table+'      <td style="width: 560px;">'+str(sv)+'</td>\n'
                    str_table = str_table+"    </tr>\n"
            else:
                str_table = str_table+'    <tr height="20px">\n'
                str_table = str_table+'      <td style="width: 140px;">'+k.title()+'</td>\n'
                str_table = str_table+'      <td style="width: 560px;">'+str(v)+'</td>\n'
                str_table = str_table+"    </tr>\n"
        str_table = str_table+"  </tbody>\n</table>\n"
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error creating the table: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return str_table

# Function to build a header for the HTML body
def create_header(in_alert,image):
    str_table = """<table style="text-align: left; width: 824px; height: 205px;" border="0" cellpadding="2" cellspacing="2">\n
      <tbody>\n
        <tr>\n
          <td style="width: 287px;"><img style="width: 132px; height: 132px;" alt="Wazuh Logo" src={}></td>\n
          <td style="width: 410px;">\n      <h1>WAZUH Alert Notification</h1></td>\n
        </tr>\n
        <tr>\n
          <td style="width: 287px; text-align: right;"><span style="font-weight: bold;">Manager</span></td>\n
          <td style="width: 410px;">{}</td>\n
        </tr>
        <tr>\n
          <td style="width: 287px; text-align: right;"><span style="font-weight: bold;">TimeStamp</span></td>\n
          <td style="width: 410px;">{}</td>\n
        </tr>\n
      </tbody>\n
    </table>\n
    """.format(image, in_alert["manager"]["name"], in_alert["timestamp"])
    return str_table

# Builds the email body from the Wazuh Alert.
def create_body(in_alert):
    str_body = "<html>\n"
    str_body = str_body+"<body>\n"
    str_body = str_body+create_header(in_alert,logo)
    str_body = str_body+"<h2>Agent Information</h2>\n"
    str_body = str_body+create_table(in_alert["agent"])
    str_body = str_body+"<br><h2>Alert Information</h2>\n"
    str_body = str_body+create_table(in_alert["rule"])
    description_added = False
    if in_alert["location"] == "EventChannel":
        str_body = str_body+"<br><h2>Windows EventChannel Alert</h2>\n"
        str_body = str_body+"<h3>System Information</h3>\n"
        str_body = str_body+create_table(in_alert["data"]["win"]["system"])
        str_body = str_body+"<h3>EventData Information</h3>\n"
        str_body = str_body+create_table(in_alert["data"]["win"]["eventdata"])
        description_added = True
    if in_alert["location"] == "syscheck":
        str_body = str_body+"<br><h2>File Integrity Monitoring Alert</h2>\n"
        str_body = str_body+create_table(in_alert["syscheck"])
        description_added = True
    if in_alert["location"] == "virustotal":
        str_body = str_body+"<br><h2>VirusTotal Alert</h2>\n"
        str_body = str_body+create_table(in_alert["data"]["virustotal"])
        description_added = True
    if in_alert["location"] == "vulnerability-detector":
        str_body = str_body+"<br><h2>Vulnerability Detector Alert</h2>\n"
        str_body = str_body+create_table(in_alert["data"]["vulnerability"])
        description_added = True
    if not description_added:
        str_body = str_body+"<br><h2>Full Alert</h2>\n"
        str_body = str_body+json.dumps(in_alert["data"], indent=4, sort_keys=True)
    return str_body

# Function to send the email alert through smtp.
def sendemail(FROM,TO,SERVER,in_alert,creds=None):
    subject = "Alert level "+str(in_alert["rule"]["level"])+" in Agent "+in_alert["agent"]["name"]+", Source: "+in_alert["location"]
    try:
        msg_body = create_body(in_alert)
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = FROM
        msg["To"] = TO
        part = MIMEText(msg_body, "html")
        msg.attach(part)
        if len(SERVER) == 1:
            server = smtplib.SMTP(SERVER[0], 30025)
            server.ehlo_or_helo_if_needed()
            result = server.sendmail(FROM, TO, msg.as_string())
        else:
        # IF using authentication
            server = smtplib.SMTP_SSL(SERVER[0], SERVER[1])
            server.login(creds[0], creds[1])
            result = server.sendmail(FROM, TO, msg.as_string())
        server.quit()
        logging.info('Successfully sent the mail to {} and alert ID: {}'.format(TO, in_alert["id"]))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Failed to send mail to {} detail: [{}] {}".format(TO, exc[2].tb_lineno, e))
        sys.exit(1)

################################################## Main Workflow ##################################################
if __name__ == "__main__":
    set_logger("custom-email-html", log_file)

    logging.info("Starting Email HTML alerts Integration")
    
    # Reading configurations and arguments
    try:
        alert_file = open(sys.argv[1])
        alert_dict = json.loads(alert_file.read())
        alert_file.close()
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Failed to load the alert: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    email_conf = read_conf(wazuh_conf)
    if len(sys.argv) == 4:
        creds = sys.argv[2].split(":")
        smtp_server = sys.argv[3].split(":")
        sendemail(email_conf["from"],email_conf["to"],smtp_server,alert_dict, creds)
    else:
        sendemail(email_conf["from"],email_conf["to"],[email_conf["server"]],alert_dict)