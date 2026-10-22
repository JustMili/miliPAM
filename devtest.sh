#!/bin/bash

read -p "Enter username: " USER

pamtester -v milipam-test "$USER" authenticate