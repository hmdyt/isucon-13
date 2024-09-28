- 初期化後にやるsshの設定
```
cat .ssh/authorized_keys | xargs -I@ sudo su -c "echo '@' > ~/.ssh/authorized_keys" isucon
```
- リッスンされているポート一覧 ```
```
sudo lsof -i -P -n | grep LISTEN
```
- vimのマクロ
	- a: 任意のキーで置換可能
	- qaでマクロ計測開始
	- やりたいアクションやる
	- qでマクロ計測終了
	- @aでマクロ実行
- vimのマクロ補足
	- 50@a で aに保存されたマクロを50回実行
	- @@は最後に実行されたマクロをもう一度実行
- システムファイルのシンボリックリンク
	- ln -s の第一引数はフルパスじゃないとダメなことに注意
```
cd /path/to/workspace
cp /etc/nginx/nginx.conf .
sudo rm /etc/nginx/nginx.conf
sudo ln -s $(readlink -f nginx.conf) /etc/nginx/nginx.conf
```
- nginxのログをalpでいい感じに見る方法
	- nginx.conf を[こんな感じ](https://github.com/tkuchiki/alp?tab=readme-ov-file#nginx)にいじる & `sudo systemctl restart nginx`
	- `cat example/logs/json_access.log | alp json`
- alp installation
```
wget https://github.com/tkuchiki/alp/releases/download/v1.0.21/alp_linux_amd64.tar.gz
tar -zxvf alp_linux_amd64.tar.gz
sudo install ./alp /usr/local/bin
```
- slow query logの設定
```
mysql -p
set global slow_query_log_file = '/tmp/slow-query.log';
set global long_query_time = 0.001;
set global slow_query_log = ON;
```
- slow query logの出力を確認
```
sudo mysqldumpslow -t 10 -s t /tmp/slow-query.log
```
- 本番ではslow query log 抜いておく
```
set global slow_query_log = OFF;
```

- 最初のスコア 2174
- slowクエリのsumで一番大きかったやつにindex貼ったら 3312
- slow クエリ top10の 単純なselect where みて index 貼ったら 4390
- GET /livestream/:id/livecomment のN+1を解消したら 7571 なった