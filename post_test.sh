#!/bin/sh
hostname=$(cat ../config/inn2-filter/nntp.server|head -1)
username=$(cat ../config/inn2-filter/nntp.username|head -1)
password=$(cat ../config/inn2-filter/nntp.password|head -1)
FROM=$(cat ../config/inn2-filter/nntp.from|head -1)
python3 post_test.py --server "$hostname" --port 563 --ssl --user "$username" --pass "$password" --from "$FROM" --subject "test $(date -u)" --newsgroups rocksolid.shared.test
