#!/usr/bin/env python

#!/usr/bin/python

# Archived Logs Removal Tool
# Created by Wazuh
import argparse
import socket
import os
import sys
import re
import logging
from time import strptime
from datetime import date, datetime, timedelta

def set_logger(name, logfile=None):
    hostname = socket.gethostname()

    format = '%(asctime)s {0} {1}: %(message)s'.format(hostname, name)

    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    #print logging.Logger.manager.loggerDict

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

def get_wazuh_log_files(source_path, days):
    hostname = socket.gethostname()

    today = datetime.now().strftime('%Y-%b-%d').split('-')
    skip_files = [
        '{0}/logs/alerts/{1}/{2}/ossec-alerts-{3}.log'.format(WAZUH_PATH, today[0], today[1], today[2]),
        '{0}/logs/alerts/{1}/{2}/ossec-alerts-{3}.json'.format(WAZUH_PATH, today[0], today[1], today[2]),
        '{0}/logs/alerts/alerts.log'.format(WAZUH_PATH),
        '{0}/logs/alerts/alerts.json'.format(WAZUH_PATH),
        '{0}/logs/archives/{1}/{2}/ossec-archive-{3}.log'.format(WAZUH_PATH, today[0], today[1], today[2]),
        '{0}/logs/archives/{1}/{2}/ossec-archive-{3}.json'.format(WAZUH_PATH, today[0], today[1], today[2]),
        '{0}/logs/archives/archives.log'.format(WAZUH_PATH),
        '{0}/logs/archives/archives.json'.format(WAZUH_PATH)
    ]

    date_limit = (datetime.now() - timedelta(days=days))
    logging.info("Collecting files in '{0}' previous to {1} ({2} days).".format(source_path, date_limit, days))

    all_files = []
    for root, dirs, files in os.walk(source_path):
        for file in files:
            file_path = "{0}/{1}".format(root, file)
            if file.endswith('json.gz') or file.endswith('json.sum'):
                m = re.search('\/(\d\d\d\d)\/(\S+)\/\S+-(\S+)-(\d+)(\.\S+.\S+)', file_path)
                if m:
                    str_year = m.group(1)
                    str_month = str(strptime(m.group(2), '%b').tm_mon).zfill(2)
                    str_alerts = m.group(3)
                    str_day = m.group(4)
                    str_extension = m.group(5)

                date_file = datetime.strptime("{0}.{1}.{2}".format(str_year, str_month, str_day), '%Y.%m.%d')

                if date_file < date_limit:
                    new_hostname = hostname
                    # Workaround: Docker
                    if '/var/lib/docker/volumes/wazuh_node' in file_path:
                        new_hostname = hostname + '_' + file_path.split('/')[5]

                    key = "/{0}/{1}/{2}/{3}/{4}{5}".format(str_year, str_month, str_day, str_alerts, new_hostname, str_extension)
                    file_path.replace('{0}/logs/alerts'.format(WAZUH_PATH), '') + "/" + new_hostname
                    date_file = "{0}{1}{2}".format(str_year, str_month, str_day)
                    new_file = {'key': key, 'path': file_path}
                    all_files.append(new_file)
                else:
                    continue
            else:
                if file_path.format(WAZUH_PATH) in skip_files:
                    continue
                if file.endswith('log.gz') or file.endswith('log.sum'):
                    continue
                logging.error("Error: File not compressed - '{0}'. Skipping.".format(file_path))

    logging.info("Files collected.")

    return all_files

def remove_wazuh_files(directory_path, days):
    remove_date_limit = (datetime.now() - timedelta(days=days))
    logging.info("Removing files previous to {0} ({1} days).".format(remove_date_limit, days))

    try:
        wazuh_files = get_wazuh_log_files(directory_path, days)
    except Exception as e:
        logging.error("Error getting Wazuh files: '{0}'.".format(str(e)))
        sys.exit(1)

    if not wazuh_files:
        logging.info("No files to remove.")
    else:
        rem_count = 0
        for item in sorted(wazuh_files, key=lambda o: tuple(o.get(a) for a in ['key'])):
            try:
                logging.info("Removing local file: '{0}'.".format(item['path']))
                os.remove(item['path'])
                rem_count += 1
            except Exception as e:
                logging.error("Error: '{0}' ('{1}') - {2}. Skipping removal.".format(item['path'], item['key'], str(e)))
        logging.info("{0} Files Removed.".format(rem_count))

if __name__ == "__main__":
    def checker(d):
        n = int(d)
        if n == 0:
            logging.error("Error: The 'days' argument must be greater than 0")
            raise argparse.ArgumentTypeError("This argument must be greater than 0")
        return n
    parser = argparse.ArgumentParser(prog="Archived Logs Removal Tool", description='Remove Logs older than X days')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-r', '--remove', action='store_true', help='Remove archived logs.')
    group.add_argument('-l', '--list', action='store_true', help='List files in the path.')
    parser.add_argument('-d', '--days', metavar='days', type=checker, required = True, help='Log retention time.')
    parser.add_argument('-p', '--path', metavar='wazuhpath', default="/var/ossec", type=str, required = True, help='Wazuh working folder.')
    parser.add_argument('-o', '--outfile', metavar='filepath', type=str, required = False, help='Log file of the tool.')
    args = parser.parse_args()

    WAZUH_PATH = args.path
    set_logger('wazuh-alrt', logfile=args.outfile)

    if args.list:
        arr_archs = get_wazuh_log_files("{0}/logs/alerts".format(WAZUH_PATH), args.days)
        if len(arr_archs) > 0:
            for arch in arr_archs:
                logging.info("Listing file {0}".format(arch["path"]))
        else:
            logging.info("Archives older than {0} days not present".format(args.days))
    if args.remove:
        remove_wazuh_files("{0}/logs/alerts".format(WAZUH_PATH), args.days)