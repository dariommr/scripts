# Description
Tool for backup archives, alerts or both to s3.
You can select if you want to upload the json compressed files, the logs compressed files or both.
The tool verify the files already in the S3 bucket to avoid the attempt to upload the same file.
The tool creates the file structure as you can find it in the `/var/ossec/logs/` folder.
You can define your credentials (and region) or make use the already configured credentials in the AWS Cli tool (do not use `[-c CREDS] [-r REGION]`).

## Syntax:
```
# python3 logs-backup-s3.py -h
usage: logs-backups-s3 [-h] [-c CREDS] [-r REGION] -b BUCKET -o {alerts,archives,both} -f {json,log,both} [-d DAYS] [--debug]

Upload archived alerts to AWS S3 bucket

optional arguments:
  -h, --help            show this help message and exit
  -c CREDS, --creds CREDS
                        AWS credentials: <access_key:secret_key>
  -r REGION, --region REGION
                        AWS region
  -b BUCKET, --bucket BUCKET
                        AWS S3 bucket name
  -o {alerts,archives,both}, --objects {alerts,archives,both}
                        Select what you want to upload
  -f {json,log,both}, --format {json,log,both}
                        Select what you want to upload
  -d DAYS, --days DAYS  Number of days to upload, if not specified it will upload all
  --debug               Enable debug mode logging.

You can use AWS CLI stored credentials, or specify different ones, also you can select between archives and alerts, and select the number of days you want to upload.
```