#!/usr/bin/bash
set -ex

cd $(dirname $0)
(cd .. && make build)
(cd ../sql && ./migration.sh)

sudo rm /var/log/nginx/access.log || true
sudo rm /tmp/slow-query.log || true

sudo systemctl restart mysql
sudo systemctl restart nginx
sudo systemctl restart isupipe-go

mysql -pisucon -e "set global slow_query_log_file = '/tmp/slow-query.log'; set global long_query_time = 0.001; set global slow_query_log = ON;"

(cd /home/isucon && ./bench run --enable-ssl)

sudo mysqldumpslow -t 10 -s t /tmp/slow-query.log
sudo cat /var/log/nginx/access.log | ./alp
