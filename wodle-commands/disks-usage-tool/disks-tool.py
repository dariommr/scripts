import argparse
import subprocess
import os, sys
import logging
from socket import socket, AF_UNIX, SOCK_DGRAM
import json

##########################  GENERAL VARIABLES  ##########################

# Disks Last Status file (If you run multiple instances of the script, do not use the same filename)
instance_name = "disks_usage.lp"

# CDB Lists location directory
lists_dir = "/var/ossec/etc/lists"

# Logs location
logs_dir = "/var/ossec/logs"

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

##########################      FUNCTIONS      ##########################

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('SENDING event {} to {} socket.'.format(msg, socketAddr))
    string = '1:disks-state-tool:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Configuring logger
def set_logger(name, level, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)

    # Start logging config
    if level == "debug":
        logging.basicConfig(level=logging.DEBUG, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    else:
        logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

# Running the df command
def run_df(sysname, part):
    if sysname == "local":
        res = subprocess.Popen(('df -l -k '+part).split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
    else:    
        res = subprocess.Popen(['ssh', sysname, "df -l -k "+part],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
    stdout,stderr = res.communicate()
    stdout_dec = stdout.decode("ascii")
    arr_stdout = stdout_dec.splitlines()
    if "Filesystem" in str(stdout):
        n = 0
        for number, line in enumerate(arr_stdout):
            if "Filesystem" in line:
                n = number
                break
        if n > 0:
            ignored = arr_stdout[:n]
            logging.warning("Unable to get all the disks in the system. Ignoring: {}.".format(str(ignored)))
        arr_stdout = arr_stdout[n+1:]
        logging.debug("Finished executing the 'df' command with result: {}.".format(stderr))
    else:
        logging.error("Error while executing the 'df' command: {}.".format(str(stdout)))
        arr_stdout = ["Error"]
    return arr_stdout

# Obtain system information, same parameters as "uname" command
def sys_info(sysname, param):
    if sysname == "local":
        res = subprocess.Popen(['uname',"-"+param],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT)
    else:
        res = subprocess.Popen(['ssh', sysname, "uname -"+param],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT)
    stdout,stderr = res.communicate()
    stdout_dec = stdout.decode("ascii")
    logging.debug("Finished executing the 'uname' command with result: {}.".format(stderr))
    return stdout_dec.strip()

# Converting the command output into a json
def convert_dict(arr_disks):
    header = ["filesystem", "blocks", "used", "available", "usePercentage", "mountedOn"]
    arr_out =[]
    try:
        for str_line in arr_disks:
            arr_line = str_line.split()
            tmp_dict = {}
            for item in header:
                value = arr_line[header.index(item)]
                if "%" in value:
                    value = value[:-1]
                tmp_dict[item] = value
            tmp_dict
            arr_out.append(tmp_dict)
    except Exception as e:
        logging.error("An error occurred while converting the data into JSON: {}".format(e))
        sys.exit(1)
    return arr_out

# Compare the Output with the reference file
def may_send(ref_dict,out_dict):
    send = False
    dsk_match = False
    sys_match = False
    if ref_dict["last-percentage"]:
        for prev_system in ref_dict["last-percentage"]:
            if prev_system["system"] == out_dict["disks-tool"]["system"]:
                sys_match = True
                for prev_disks in prev_system["disks"]:
                    if prev_disks["filesystem"] == out_dict["disks-tool"]["disk_info"]["filesystem"]:
                        dsk_match = True
                        send = (prev_disks["usePercentage"] != out_dict["disks-tool"]["disk_info"]["usePercentage"])
                        break
                if not dsk_match:
                    send = True
                    break
        if not sys_match:
            send = True
    else:
        send = True
    return send

##########################    MAIN PROGRAM     ##########################

if __name__ == "__main__":
    # Parsing the arguments
    epilogue = "This tool requires a communication with the destination hosts with a trusted ssh, it means by certificates."
    parser = argparse.ArgumentParser(prog="get-disks-usage", description='Get disks usage from remote systems', epilog=epilogue)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--system', metavar='<target_system>', nargs='+', help='Name of the systems to extract the information. Can not use --syslist with this option')
    group.add_argument('--syslist', help='File with the list of systems to be queried. Can not use --system with this option')
    parser.add_argument('--disks', help='The disks you need to query for status')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()
    if args.debug:
        set_logger(instance_name, "debug", os.path.join(logs_dir, "disks-usage.log"))
    else:
        set_logger(instance_name, "info", os.path.join(logs_dir, "disks-usage.log"))

    logging.info("------- Starting the Disks Usage Tool -------")
    # Getting the servers
    if args.syslist:
        logging.info("Using a list of servers from CDB List: {}".format(args.syslist))
        list_name = args.syslist
        try:
            cdb_list = os.path.join(lists_dir, list_name)
            file_list = open(cdb_list, "r")
            sys_list = file_list.readlines()
            logging.info("List of servers loaded successfully")
        except Exception as e:
            logging.error("Failed to load the servers list: {}".format(e))
            sys.exit(1)
    if args.system:
        logging.info("Using a server from the command parameter")
        sys_list = args.system
        disks = args.disks
    logging.info("Parameters loaded successfully")

    # Look for the database file
    instance_path = os.path.join("/var/ossec/wodles/", instance_name)
    if os.path.isfile(instance_path) and os.path.getsize(instance_path) > 0:
        file_db = open(instance_path, "r")
        sys_dict = json.loads(file_db.read())
        logging.info("Retrieved the last status of the disks from DB")
    else:
        sys_dict = {}
        sys_dict["last-percentage"] = []
        logging.info("No last status from the DB, creating it")

    logging.info("Contacting servers to extract the disks status")
    for system_line in sys_list:
        if args.syslist:
            arr_line = system_line.split(":")
            system_line = arr_line[0].strip()
            if "@" in system_line:
                system = system_line.split("@")[1]
            else:
                system = system_line
            disks = arr_line[1].strip()
        else:
            system = system_line.split("@")[1]
        logging.debug("Obtaining the status of the disks {} for system: {}".format(disks, system))
        cmd_res = run_df(system_line, disks)
        if cmd_res == ["Error"]:
            break
        event = {}
        event["disks-tool"] = {}
        sys_hostname = sys_info(system_line, "n")
        event["disks-tool"]["systemIP"] = system
        event["disks-tool"]["system"] = sys_hostname
        tmp_dict = {}
        tmp_dict["system"] = sys_hostname
        tmp_dict["disks"] = []
        for disk in convert_dict(cmd_res):
            tmp_dict["disks"].append(disk)
            event["disks-tool"]["disk_info"] = disk
            json_event = json.dumps(event)
            # Send the event to Wazuh if the use percentage changed
            if may_send(sys_dict, event):
                send_event(json_event)
            else:
                logging.debug("No changes encountered IGNORING event: {}".format(json_event))
        # Si existe la entrada para dicho sistema, la actualiza con la nueva informacion
        for x in sys_dict["last-percentage"]:
            if x["system"] == sys_hostname:
                sys_dict["last-percentage"].remove(x)
        sys_dict["last-percentage"].append(tmp_dict)
    logging.info("Disks status extracted and processed. Writing the status file: {}".format(instance_name))
    file_db = open(instance_path, "w")
    file_db.write(json.dumps(sys_dict))
    file_db.close()
    logging.info("------- Finished the Disks Usage Tool -------")