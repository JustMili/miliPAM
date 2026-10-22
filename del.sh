#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "You need root dumbass." 
   exit 1
fi

rm -rf /var/lib/milipam/
rm -rf /etc/milipam/

echo "done"