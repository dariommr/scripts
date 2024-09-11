# !/usr/bin/python3
import boto3
import os, sys
import argparse
import logging
from datetime import datetime, timedelta

################################################## Global variables ##################################################

DEBUG = False
op_logs = "/var/log/logs-backup-s3.log"
logs_location = "/var/ossec/logs/"

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

# Collects the list of files to be uploaded
def get_file_list(format, days=None):
    if days != None:
        lower_bound = datetime.now() - timedelta(days=int(days))
    arr_files = []
    for subdir, dirs, files in os.walk(PATH):
        for file in files:
            if format == "both":
                condition = file.endswith(".gz")
            else:
                condition = file.endswith("."+format+".gz")
            if condition:
                full_path = os.path.join(subdir, file)
                if days == None:
                    arr_files.append(full_path)
                else:
                    if datetime.fromtimestamp(os.path.getmtime(full_path)) > lower_bound:
                        arr_files.append(full_path)
    return arr_files

# Collects the list of files in the bucket s3
def get_files_s3(s3_obj, bucket_name):
    my_bucket = s3_obj.Bucket(bucket_name)
    arr_s3_files = []
    for s3_file in my_bucket.objects.all():
        full_s3 = os.path.join(logs_location, s3_file.key)
        arr_s3_files.append(full_s3)
    return arr_s3_files

################################################## Main Program #####################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="logs-backups-s3",
        description="Upload archived alerts to AWS S3 bucket",
        epilog="You can use AWS CLI stored credentials, or specify different ones, also you can select between archives and alerts, and select the number of days you want to upload."
        )
    parser.add_argument('-c', '--creds', type=str, required=False, help='AWS credentials: <access_key:secret_key>')
    parser.add_argument('-r', '--region', type=str, required=False, help='AWS region')
    parser.add_argument('-b', '--bucket', type=str, required=True, help='AWS S3 bucket name')
    accepted_objects = ["alerts", "archives", "both"]
    parser.add_argument('-o', '--objects', type=str, choices=accepted_objects, required=True, help='Select what you want to upload')
    accepted_formats = ["json", "log", "both"]
    parser.add_argument('-f', '--format', type=str, choices=accepted_formats, required=True, help='Select what you want to upload')
    parser.add_argument('-d', '--days', type=str, required=False, help='Number of days to upload, if not specified it will upload all')
    parser.add_argument('--debug', action='store_true', required=False, help='Enable debug mode logging.')
    args = parser.parse_args()

    if args.debug:
        DEBUG = True
    set_logger("logs-backup-s3", op_logs)
    logging.info("# Starting the backups script")
    try:
        if args.creds:
            if not args.region:
                #parser.print_help(sys.stderr)
                raise Exception("AWS Region not specified, please use -r/--region to specify one")
            arr_creds = args.creds.split(":")
            session = boto3.Session(
                aws_access_key_id=arr_creds[0],
                aws_secret_access_key=arr_creds[1],
                region_name=args.region
            )
            s3 = session.resource('s3')
        else:
            s3 = boto3.resource('s3')
        logging.info("Connected to AWS S3 resource")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error connecting to AWS: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    if args.objects == "both":
        base_path = logs_location
        logging.debug("Selected to upload archives and alerts")
    else:
        base_path = os.path.join(logs_location, args.objects)
        logging.debug("Selected to upload only {}".format(args.objects))
    PATH = base_path

    try:
        if args.days:
            all_files = get_file_list(args.format, args.days)
        else:
            all_files = get_file_list(args.format)
        logging.info("List of files generated successfully. Number of files retrieved: {}".format(len(all_files)))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining list of files: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    list_s3 = []
    try:
        list_s3 = get_files_s3(s3, args.bucket)
        logging.info("List of s3 objects generated successfully. Number of objects retrieved: {}".format(len(list_s3)))
    except Exception as e:
        exc = sys.exc_info()
        logging.warning("Error obtaining list of s3 objects: [{}] {}".format(exc[2].tb_lineno, e))

    final_list = [i for i in all_files if i not in list_s3]
    logging.info("Final list of files generated successfully. Number of files to upload: {}".format(len(final_list)))

    try:
        for file in all_files:
            s3_key = file.replace(logs_location, "")
            s3.meta.client.upload_file(file, args.bucket, s3_key)
            logging.debug("File uploaded successfully: {}".format(s3_key))
        logging.info("All files uploaded successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error uploading files: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
