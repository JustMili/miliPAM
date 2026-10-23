#!/bin/bash

set -e

if [[ $EUID -ne 0 ]]; then
   echo "You need root dumbass." 
   exit 1
fi


PAM_DIR=""
if [ -d "/usr/lib64/security" ]; then
    PAM_DIR="/usr/lib64/security"
elif [ -d "/usr/lib/security" ]; then
    PAM_DIR="/usr/lib/security"
elif [ -d "/lib/x86_64-linux-gnu/security" ]; then
    PAM_DIR="/lib/x86_64-linux-gnu/security"
else
    PAM_DIR="/usr/lib/security"
fi


if [ -f "$PAM_DIR/pam_milipam.so" ]; then
    rm -f "$PAM_DIR/pam_milipam.so"
fi
cp pam_milipam.so "$PAM_DIR/"
chown root:root "$PAM_DIR/pam_milipam.so"
chmod 755 "$PAM_DIR/pam_milipam.so"

if [ -f "/usr/bin/milipam" ]; then
    rm -f "/usr/bin/milipam"
fi
cp milipam /usr/bin/milipam
chown root:root /usr/bin/milipam
chmod 755 /usr/bin/milipam

if [ -f "/usr/bin/milipam_helper" ]; then
    rm -f "/usr/bin/milipam_helper"
fi
cp milipam_helper /usr/bin/milipam_helper
chown root:root /usr/bin/milipam_helper
chmod 4755 /usr/bin/milipam_helper


mkdir -p /var/lib/milipam/
mkdir -p /var/lib/milipam/psw
mkdir -p /etc/milipam/

if [ ! -f "/var/lib/milipam/data.json" ]; then
    echo "{}" > "/var/lib/milipam/data.json"
fi

if [ ! -f "/etc/milipam/config.json" ]; then
    echo "{}" > "/etc/milipam/config.json"
fi

if [ ! -f "/var/lib/milipam/data.lock" ]; then
    touch "/var/lib/milipam/data.lock"
fi


chown -R root:root /var/lib/milipam
chown -R root:root /etc/milipam

chmod 700 /var/lib/milipam
chmod 700 /var/lib/milipam/psw
chmod 700 /etc/milipam

chmod 600 /var/lib/milipam/data.json
chmod 600 /etc/milipam/config.json
chmod 600 /var/lib/milipam/data.lock

echo "done"