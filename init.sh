#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "You need root dumbass." 
   exit 1
fi

mkdir -p /var/lib/milipam/
mkdir -p /var/lib/milipam/psw
mkdir -p /etc/milipam/

if [ ! -f "/var/lib/milipam/data.json" ]; then
    echo "{}" > "/var/lib/milipam/data.json"
fi

if [ ! -f "/etc/milipam/config.json" ]; then
    echo "{}" > "/etc/milipam/config.json"
fi

chown -R root:root /var/lib/milipam
chown -R root:root /var/lib/milipam/psw
chown -R root:root /etc/milipam

chmod 700 /var/lib/milipam
chmod 700 /var/lib/milipam/psw
chmod 700 /etc/milipam

chmod 600 /var/lib/milipam/data.json
chmod 600 /etc/milipam/config.json

echo "done"