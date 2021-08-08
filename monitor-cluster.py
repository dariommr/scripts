#/var/ossec/framework/python/bin/python3
# Wazuh Cluster Monitoring Tool
# Usage:
#       monitor-cluster.py update|status
# Parameters:
#       update     Use this to create, or update the baseline file
#       status     Gets the current status of the cluster
# No parameters: The tool runs in automatic mode, if the baseline file is not crated
#                it creates it, if not it runs the status check.

import os
from subprocess import PIPE, Popen
import yaml
import json
import xml.etree.ElementTree as ET
import sys
from datetime import datetime
import re

# Initial configurations
conf_file = "/var/ossec/etc/ossec.conf"
cluster_conf = "cluster-initial.yml"
control_bin = "/var/ossec/bin/cluster_control -l"

# Function to log messages on json format.
#    levels: INFO, WARN, ERROR
#    types: command, config, compare, resul, main
#    out: output type, for now only "stdout" is available.
def mylogger_json(level, type, message, out):
    name = "wazuh-cluster-monitor"
    log_dict = {}
    log_dict[name] = {}
    log_dict[name]["timestamp"] = str(datetime.now())
    log_dict[name]["hostname"] = os.uname()[1]
    log_dict[name]["type"] = type
    log_dict[name]["severity"] = level
    log_dict[name]["message"] = message
    log_json = json.dumps(log_dict, separators=(",", ":"))
    if out == "stdout":
        print(log_json)
    return log_json

# Function to query the cluster status through the "cluster_control -l" command
def get_status():
    mylogger_json("INFO", "command", "Getting the current status of the cluster from the command <cluster_control>", "stdout")
    try:
        process = Popen(control_bin, shell=True, stdout=PIPE, stderr=PIPE)
        res, stderr = process.communicate()
        if stderr:
            error_str = (stderr.strip()).decode('ascii')
            mylogger_json("ERROR", "command", error_str, "stdout")
            quit()
    except OSError as e:
        mylogger_json("ERROR", "command", "Unable to execute cluster_control: "+e.strerror, "stdout")
        quit()
    arr_res = (res.decode('ascii')).splitlines()
    header = arr_res.pop(0)
    arr_header = header.split()
    nodes = {}
    i=0
    for line in arr_res:
        arr_line = line.split()
        i+=1
        num="node-"+str(i)
        nodes[num] = {}
        for x in range(0,len(arr_line)):
            nodes[num][arr_header[x].lower()] = arr_line[x]
    return nodes

# Function to read the "ossec.conf" file from its location and extract the cluster configuration.
def get_config(conf_file_path):
    mylogger_json("INFO", "config", "Getting the cluster configuration from ossec.conf", "stdout")
    if os.path.exists(conf_file_path):
        xml_file = open(conf_file_path)
        xml_string = xml_file.read()
        re_conf = re.sub("^<!--", "<root>\n<!--", xml_string) + "\n</root>"
        ossec_conf = ET.fromstring(re_conf)
        cluster_xml = ossec_conf[0].findall('cluster')
        if cluster_xml == []:
            mylogger_json("ERROR", "config", "No <cluster> tag found in ossec.conf", "stdout")
            quit()
        cluster = {}
        cluster["cluster"] = {}
        for elem in cluster_xml[0]:
            if elem.tag == "nodes":
                cluster["cluster"]["master"] = elem[0].text
            else:
                cluster["cluster"][elem.tag] = elem.text
        return cluster
    else:
        mylogger_json("ERROR", "config", "Unable to open the configuration file ossec.conf", "stdout")
        quit()

# Function to write in the "cluster-initial.yml" the current state of the
# cluster in order to define an initial status and then
# compare the future states with this baseline
def initial_conf(cl_conf):
    data = get_config(conf_file)
    data["nodes"] = get_status()
    data["cluster"]["nodes"] = len(data["nodes"])
    try:
        data["cluster"].pop("bind_addr")
        data["cluster"].pop("node_name")
        data["cluster"].pop("node_type")
        data["cluster"].pop("papa")
    except:
        exit
    mylogger_json("INFO", "config", "Saving the current status of the cluster in the file "+cl_conf, "stdout")
    init_conf = open(cl_conf, 'w')
    init_conf.write(yaml.dump(data))
    init_conf.close
    return data

# Function to compare the information from the cluster_control command and
# the information obtained from the "cluster-initial.yml" file
def compare_dict(cl_conf):
    mylogger_json("INFO", "compare", "Comparing the current status of the cluster with the configuration file ", "stdout")
    init_conf = open(cl_conf, 'r')
    conf_lines = init_conf.read()
    init_conf.close
    dict_conf = yaml.safe_load(conf_lines)
    dict_data = {}
    dict_data["nodes"] = get_status()
    arr_conf = []
    for node in dict_conf["nodes"]: arr_conf.append(dict_conf["nodes"][node]["name"])
    arr_data = []
    for node in dict_data["nodes"]: arr_data.append(dict_data["nodes"][node]["name"])
    diff1 = list(set(arr_conf) - set(arr_data))
    diff2 = list(set(arr_data) - set(arr_conf))
    res = {}
    if diff1 != []:
        res["result"] = "Node[s] were removed. Please check the nodes health"
        res["nodes"] = diff1
        mylogger_json("ERROR", "result", res, "stdout")
    else:
        if diff2 != []:
            res["result"] = "New node[s] were added. Please update the configuration file"
            res["nodes"] = diff2
            mylogger_json("WARN", "result", res, "stdout")
        else:
            res["result"] = "no_changes"
            res["nodes"] = []
            mylogger_json("INFO", "result", res, "stdout")
    return res

# Main Program
if __name__ == '__main__':
    if len(sys.argv) == 1:
        mylogger_json("INFO", "main", "Running in automatic mode, no arguments were passed", "stdout")
        if os.path.exists(cluster_conf):
            mylogger_json("INFO", "main", "Running the status mode", "stdout")
            comp = compare_dict(cluster_conf)
        else:
            mylogger_json("INFO", "main", "Running the update mode", "stdout")
            res_init = initial_conf(cluster_conf)
    else:
        mylogger_json("INFO", "main", "Running in manual mode, arguments were passed", "stdout")
        option = sys.argv[1]
        if option == "update":
            mylogger_json("INFO", "main", "Running the update mode", "stdout")
            res_init = initial_conf(cluster_conf)
        else:
            if option == "status":
                mylogger_json("INFO", "main", "Running the status mode", "stdout")
                comp = compare_dict(cluster_conf)
            else:
                mylogger_json("WARN", "main", "No valid arguments were passed", "stdout")
    mylogger_json("INFO", "main", "Finished monitoring the cluster status", "stdout")
