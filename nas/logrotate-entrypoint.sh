#!/bin/sh
set -eu

while :; do
    logrotate --state /tmp/logrotate.state /etc/logrotate.conf
    sleep 60
done
