#!/usr/bin/env bash

#input validation
regex='^[0-9]+$'
var1=30

if [[ -z "$1" ]]; then
	echo "Default time used: every ${var1}th min cronjob"
elif [[ $1 =~ $regex ]]; then 
	var1="$1"
else
    echo "Invalid input, default time used: every ${var1}th min"
    var1=30
fi

#every ($var1)th minute, need to specify python
scan_frequency="*/$var1 * * * * /usr/bin/python3 ./netpi.py --scan-log" 
perf_frequency="*/$var1 * * * * /usr/bin/python3 ./netpi.py --perf-log"

#check if crontab exists already, suppress stderr and reg. output   
if crontab -l > /dev/null 2>&1 ; then 
    #check if cronjob exists already
    if crontab -l 2>/dev/null | grep -q "./netpi.py --scan-log"; then
    echo "cronjob already exists for $USER"
    else 
    echo "Adding cronjob to ${USER}'s crontab"
    #Thanks to stackoverflow
    (crontab -l 2>/dev/null; echo "$scan_frequency") | crontab - 
    echo "Added cronjob to ${USER}'s crontab"
    fi
else 
    echo "No crontab exists, creating new crontab for $USER"
    echo "$scan_frequency" | crontab -
fi 

#Same thing but for performance cronjob
if crontab -l > /dev/null 2>&1 ; then 
    #check if cronjob exists already
    if crontab -l 2>/dev/null | grep -q "./netpi.py --perf-log"; then
    echo "cronjob already exists for $USER"
    else 
    echo "Adding cronjob to ${USER}'s crontab"
    #Thanks to stackoverflow
    (crontab -l 2>/dev/null; echo "$perf_frequency") | crontab - 
    echo "Added cronjob to ${USER}'s crontab"
    fi
else 
    echo "No crontab exists, creating new crontab for $USER"
    echo "$perf_frequency" | crontab -
fi 