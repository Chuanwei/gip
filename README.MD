# 0x00功能：

集合多个接口的IP反查域名工具。

# 0x01命令行运行
```python
python3 gip.py

usage: gip.py [-h] [-i IP | -f FILE]

     _/_/_/  _/_/_/  _/_/_/    
  _/          _/    _/    _/   
 _/  _/_/    _/    _/_/_/      
_/    _/    _/    _/           
 _/_/_/  _/_/_/  _/    集合多个接口的IP反查域名工具。注意：使用virustotal接口需配置Key！
API：webscan, rapiddnsio, ip138, ipchaxun, aizhan, dnsgrep, viewdns, virustotal

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        指定单个IP
  -f FILE, --file FILE  从文件批量IP
```
# 0x02使用方法

python gip.py -i 103.41.167.234

python gip.py -f target.txt
  
  
  
