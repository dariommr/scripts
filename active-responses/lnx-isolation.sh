#!/bin/bash
allowed_hosts=(<IP1> <IP2>)
log_file=/var/ossec/logs/active-responses.log

read alert_input

logger() {
    hostname=$(hostname)
    process="lnx-isolation"
    now=$(date +'%m/%d/%Y %H:%M:%S')
    case $1 in
        "-e")
            mtype="[ERROR]"
            message="$2"
            ;;
        "-w")
            mtype="[WARNING]"
            message="$2"
            ;;
        *)
            mtype="[INFO]"
            message="$1"
            ;;
    esac
    echo $now $hostname $process: $mtype $message >>$log_file
}

gate_cmd=$(ip route | grep default)
regex="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
if [[ $gate_cmd =~ $regex ]]; then
    gateway=${BASH_REMATCH[1]}
fi
allowed_hosts[${#allowed_hosts[@]}]=$gateway

regex='.*"extra_args":\["([a-z]*)"\].*'
if [[ $alert_input =~ $regex ]]; then
    extra_args=${BASH_REMATCH[1]}
fi

regex='.*"id":"([a-z1-9]*)"\}.*'
if [[ $alert_input =~ $regex ]]; then
    alert_id=${BASH_REMATCH[1]}
fi

if [[ $extra_args == "add" ]]; then
    logger "Starting Active Response for alert: "$alert_id
    iptables-save >iptables.bkp
    iptables -F

    iptables -t filter -P INPUT DROP
    iptables -t filter -P FORWARD DROP
    iptables -t filter -P OUTPUT DROP

    iptables -t filter -A INPUT -i lo -j ACCEPT
    iptables -t filter -A OUTPUT -o lo -j ACCEPT

    for host in ${allowed_hosts[*]}; do
        iptables -t filter -A INPUT -s $host -j ACCEPT
        iptables -t filter -A OUTPUT -d $host -j ACCEPT
    done
fi

if [[ $extra_args == "delete" ]]; then
    logger "Rolling back Active Response for alert: "$alert_id
    if test -f "iptables.bkp"; then
        iptables-restore <iptables.bkp
        rm -f iptables.bkp
    else
        logger -e "No backup file to recover"
    fi
fi

if ! [[ $extra_args == "add" ]] && ! [[ $extra_args == "delete" ]]; then
    logger -e "Wrong command sent"
fi
