# 0x00功能

集合多个接口的IP反查域名工具。

# 0x01接口

API：webscan, rapiddnsio, ip138, ipchaxun, aizhan, dnsgrep, viewdns, virustotal

注意：virustotal需配置key才能生效！

# 0x02使用方法

#安装

pip3 install requirements.txt

# 配置virustotal key
```
vi gip.py
default_vt_key = '你的API KEY'
```
#单个ip

python3 gip.py -i 103.41.167.234

#批量

python3 gip.py -f target.txt
  
  
  
