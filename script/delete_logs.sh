#!/usr/bin/bash

set -ex

sudo rm /var/log/nginx/access.log
sudo systemctl restart nginx