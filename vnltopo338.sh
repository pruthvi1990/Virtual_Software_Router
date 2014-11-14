#!/bin/bash
# Virtual Network Lab, soft host connecting script
topoid=338
if [ "$1" = '' ]
then
	echo $0 gateway ...
	echo $0 vrhost ...
	echo $0 server1 ...
	echo $0 server2 ...
	echo $0 server3 ...
	echo $0 server4 ...
	exit 1
fi
if [ ! -f vnltopo$topoid.sshconfig ]; then echo 'sshconfig missing' >/dev/stderr; exit 1; fi
if [ ! -f vnltopo$topoid.pvtkey ]; then echo 'pvtkey missing' >/dev/stderr; exit 1; fi
chown `id -u`:`id -g` vnltopo$topoid.pvtkey
chmod 600 vnltopo$topoid.pvtkey
ssh -F vnltopo$topoid.sshconfig "$@"
