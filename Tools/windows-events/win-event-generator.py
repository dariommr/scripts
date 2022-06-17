from datetime import datetime
import time
import random
import json

source_file = open("WindowsSecurityAuditEvents.csv", "r")
data = source_file.readlines()
source_file.close()

def random_line(afile):
    line = afile[0]
    for num, aline in enumerate(afile, 2):
        if random.randrange(num):
            continue
        line = aline
    return line

sample_users = ["dariommr", "Administrator", "backup_user", "johnd", "janed", "sqlsvc_user", "anakins", "lukes", "leias", "hans"]
event = {}
event["win"] = {}
event["win"]["system"] = {}
event["win"]["eventdata"] = {}
while True:
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    arr_line = random_line(data).split(";")
    event["win"]["system"]["systemTime"] = timestamp
    event["win"]["system"]["eventID"] = arr_line[2]
    event["win"]["system"]["channel"] = "Security"
    event["win"]["system"]["severityValue"] = "INFORMATION"
    event["win"]["system"]["message"] = arr_line[3]
    event["win"]["system"]["providerName"] = "Microsoft-Windows-Security-Auditing"
    event["win"]["system"]["level"] = "0"
    event["win"]["system"]["computer"] = "DC01.contoso.local"
    event["win"]["eventdata"]["subjectUserName"] = sample_users[random.randint(0,9)]
    event["win"]["eventdata"]["targetUserName"] = sample_users[random.randint(0,9)]
    log_file = open("win-events-log.log", "a")
    log_file.write(json.dumps(event)+"\n")
    log_file.close()
    #print(json.dumps(event))
    time.sleep(1)
