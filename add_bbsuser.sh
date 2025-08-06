#!/bin/bash -e
username=$(pwgen -s 12 -1)
test ! -z "$1" && username="$1"
password=$(pwgen -s 12 -1)
HASH=$(openssl passwd -5 "$password")
echo "$username:$HASH" >> /etc/news/bbsuser.passwd
echo "$username:$password|$(date +%s)" >> /etc/news/bbsuser.created.log
echo "created username: '$username' with password: '$password'"

