#!/bin/sh

IDX=`hostname -i|awk -F "." '{print $4-62}'`
IP=192.168.83.$IDX
ifconfig br-ctl $IP/24
