# 0x00功能

集合多个接口的IP反查域名工具。

# 0x01接口

API：webscan, rapiddnsio, ip138, ipchaxun, aizhan, dnsgrep, viewdns, virustotal

注意：
virustotal需配置自己的key

dnslytics需要配置自己的cookie

# 0x02使用方法

#安装

pip3 install requirements.txt

#配置virustotal key
```
vi gip.py
api_key = {
        "virustotal": {"api_key": "你的key"},
        "xxx": {"api_key": ""}
    }
```
#单个ip

python3 gip.py -i 103.41.167.234

#批量

python3 gip.py -f target.txt

# 0x03接受建议

如有建议的接口欢迎提交issue
