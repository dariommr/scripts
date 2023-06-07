#!/var/ossec/framework/python/bin/python3
import os, sys
from socket import socket, AF_UNIX, SOCK_DGRAM
import subprocess
import xmltodict
import json
import logging

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Location of the log file. Set it in <None> if no need for logfile
logfolder = "/var/ossec/logs"
DEBUG = False

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

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:ports_scan:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

def run_nmap(target):
    try:
        ofile = "nmap-results.xml"
        p = subprocess.Popen("nmap "+target+" -oX "+ofile, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        logging.debug("Executed nmap: {}".format(out))
        if err:
            raise Exception(err)

        xml_file = open(ofile, 'r', encoding='utf-8')
        xml_lines = xml_file.read()

        xml_dict = xmltodict.parse(xml_lines, attr_prefix='')
        wazuh_alert = {}
        wazuh_alert["ports-scan"] = xml_dict["nmaprun"]["host"]
        os.remove(ofile)
        logging.debug("XML output converted to JSON")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error executing nmap: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    return json.dumps(wazuh_alert)

################################################## Main workflow ##################################################

if __name__ == "__main__":
    log_file = os.path.join(logfolder, "active-responses.log")
    set_logger("ports-scan", log_file)
    logging.info("Ports-Scan Active Response Started")
    alert_input = sys.stdin.readline()
    try:
        alert_dict = json.loads(alert_input)
        srcip = alert_dict["parameters"]["alert"]["data"]["srcip"]
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error reading input: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    
    logging.info("Executing the AR for the alert ID: {}".format(alert_dict["parameters"]["alert"]["id"]))
    get_ports = run_nmap(srcip)
    send_event(get_ports)
    logging.debug("Sent message to Wazuh: {}".format(get_ports))
    logging.info("Ports-Scan Active response Finished")