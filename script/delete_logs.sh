#!/usr/bin/bash

set -ex

sudo rm /tmp/slow-query.log
sudo rm /var/log/nginx/access.log
sudo systemctl restart nginx