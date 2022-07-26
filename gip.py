#!/usr/bin/python3
# -*- coding: utf-8 -*-
# version: 2.1

import re, time, sys, csv, json
import argparse
import requests
import urllib3
import threading
from traceback import format_exc
import logging
# 以下为依赖库
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup as BS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
FORMAT = '[%(asctime)-15s] [%(levelname)s] [%(filename)s %(levelno)s line] %(message)s'
logger = logging.getLogger(__file__)
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

def webscan(ip):
    domain_list = []
    url = r'http://api.webscan.cc/?action=query&ip={}'.format(ip)
    # regx = re.compile(r'{"domain":"http:\\/\\/(.*?)","title":".*?"}')
    headers = {
        'Use-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        'Referer': "https://webscan.cc/"
    }
    res = requests.get(url=url, headers=headers, timeout=10, verify=False)
    results = json.loads(res.text)
    count = 0
    for domain in results:
        if count < 20:
            data = {"source": 'aizhan', "ip": ip, "domain": domain["domain"], "date": ''}
            data.update(url_title(domain["domain"]))
            domain_list.append(data)
            count = count + 1
    return domain_list


def rapiddnsio(ip):
    domain_list = []
    session = requests.session()
    sessions = session.get("https://rapiddns.io")
    html = session.get("https://rapiddns.io/s/%s#result" % ip)
    df = pd.read_html(html.content)[0]
    count = 0
    for i, line in df.iterrows():
        if count < 20:
            data = {'source': 'rapiddns.io', 'ip': ip, 'domain': line["Domain"], 'date': line["Date"]}
            data.update(url_title(line["Domain"]))
            domain_list.append(data)
            count = count + 1
    return domain_list


def ip138(ip):
    domain_list = []
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Host': 'site.ip138.com',
        'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/87.0.4280.77 Mobile/15E148 Safari/604.1 Edg/100.0.4896.127'
    }
    domain_re = re.compile(r'class="date">(.*?)</span><a href="/(.*?)/"')
    url = 'https://site.ip138.com/' + ip
    req = requests.get(url, headers=headers, timeout=3)
    domains = domain_re.findall(req.text)
    count = 0
    for domain in domains:
        if count < 20:
            data = {"source": 'ip138', "ip": ip, "domain": domain[1], "date": domain[0]}
            data.update(url_title(domain[1]))
            domain_list.append(data)
            count = count + 1
    return domain_list


def ipchaxun(ip):
    domain_list = []
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Host': 'ipchaxun.com',
        'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/87.0.4280.77 Mobile/15E148 Safari/604.1 Edg/100.0.4896.127'
    }
    domain_re = re.compile(r'class="date">(.*?)</span>\s<a href="/(.*?)/"')
    url = 'https://ipchaxun.com/' + ip
    req = requests.get(url, headers=headers, timeout=3)
    domains = domain_re.findall(req.text)
    count = 0
    for domain in domains:
        if count < 20:
            data = {"source": 'ipchaxun', "ip": ip, "domain": domain[1], "date": domain[0]}
            data.update(url_title(domain[1]))
            domain_list.append(data)
            count = count + 1
    return domain_list


def dnsgrep(ip):
    domain_list = []
    domain_re = re.compile(r'<tr>[\s\S]*?<td data="(.*?)">[\s\S]*?class="date">(.*?)</td>')
    url = 'https://www.dnsgrep.cn/ip/' + ip
    req = requests.get(url, timeout=5)
    domains = domain_re.findall(req.text)
    count = 0
    for i in domains:
        if count < 20:
            data = {"source": 'dnsgrep', "ip": ip, "domain": i[0], "date": i[1]}
            data.update(url_title(i[0]))
            domain_list.append(data)
            count = count + 1
    return domain_list


def aizhan(ip):
    # aizhan_Cookie_zhonghua = '_csrf=016a9c50bdff06f4cc824d329c670f2d46e52143a02ed60d21a7da58e7c9b3c5a%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22_csrf%22%3Bi%3A1%3Bs%3A32%3A%22dAuCPnTC_6PUUOr_kvoDdV-bhCI7-5KV%22%3B%7D; Hm_lvt_b37205f3f69d03924c5447d020c09192=1650288526;userId=1416679; userName=506130869%40qq.com; userGroup=1; userSecure=wCb9HEVFh9%2FNdyGQgPo2RcVH3YYQyJJ1Dtf1fqMdP0wpLj0G3ZPjHLCy%2B68sGkjujJnlxn3tCokmEjaMIjXLjYgc%2FA0Pc8tpXe6aU6bv9pVlt7nWFIHUAusUvls%3D; Hm_lpvt_b37205f3f69d03924c5447d020c09192=1650289051'
    domain_list = []
    url = f'https://dns.aizhan.com/{ip}/'
    regx = r'" rel="nofollow" target="_blank">(.*?)</a>'
    headers = {
        'Use-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        'Referer': "https://dns.aizhan.com/"
    }
    res = requests.get(url=url, headers=headers, timeout=5, verify=False)
    results = re.findall(regx, res.text)
    count = 0
    for domain in results:
        if count < 20:
            data = {"source": 'aizhan', "ip": ip, "domain": domain, "date": ''}
            data.update(url_title(domain))
            domain_list.append(data)
            count = count + 1
    return domain_list


def viewdns(ip):
    domain_list = []
    url = f'https://viewdns.info/reverseip/?host={ip}&t=1'
    headers = {
        'user-agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        'referer': "https://viewdns.info/",
    }
    res = requests.get(url=url, headers=headers, timeout=10, verify=False)
    regx = r'<tr> <td>(.*?)</td><td align="center">(.*?)</td></tr>'
    results = re.findall(regx, res.text)
    count = 0
    for i in results:
        if count < 20:
            data = {"source": 'viewdns', "ip": ip, "domain": i[0], "date": i[1]}
            data.update(url_title(i[0]))
            domain_list.append(data)
            count = count + 1
    return domain_list

def virustotal(ip, vt_key=None):
    domain_list = []
    global default_vt_key
    key = vt_key if vt_key else default_vt_key
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions'
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36',
        'x-apikey': key
    }
    res = requests.get(url=url, headers=headers, timeout=10, verify=False)
    count = 0
    for i in json.loads(res.text)['data']:
        if count < 20:
            domain = i['attributes']['host_name']
            date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i['attributes']['date']))
            data = {"source": 'virustotal', "ip": ip, "domain": domain, "date": date}
            data.update(url_title(domain))
            domain_list.append(data)
            count = count + 1
    return domain_list


def dnslytics(ip, cookie=None):
    # 需要cookie
    domain_list = []
    url = 'https://dnslytics.com/reverse-ip'
    cookie = '_ga=GA1.2.1285059985.1652078154; cf_clearance=VztHrARheZ22IriqtxKY2aZplxUA.J2GZ5uUD0Qx48Y-1652261250-0-250; _gid=GA1.2.1261869202.1654748913; _gat=1'
    data = {'reverseip': ip}
    headers = {
        'Host': 'dnslytics.com',
        'Content-Length': '25',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"',
        'sec-ch-ua-mobile': '?0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://dnslytics.com',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': cookie
    }
    req = requests.post(url, data=data, headers=headers, timeout=10)
    domain_re = re.compile(r'name="whois" value="(.*?)"><input class="')
    domains = domain_re.findall(req.text)
    count = 0
    for domain in domains:
        if count < 20:
            data = {"source": 'dnslytics', "ip": ip, "domain": domain}
            data.update(url_title(domain))
            domain_list.append(data)
            count = count + 1
    return domain_list


class MyThread(threading.Thread):
    def __init__(self, func, name, args=()):
        super(MyThread, self).__init__()
        self.func = func
        self.args = args
        self.name = name
        self.exit_code = 0
        self.exception = None
        self.exc_traceback = ''

    def run(self):
        try:
            self._run()
        except Exception as e:
            self.exit_code = 1
            self.exception = e
            self.exc_traceback = format_exc()

    def _run(self):
        try:
            self.result = self.func(*self.args)
        except Exception as e:
            raise e

    # def run(self):
    #     self.result = self.func(*self.args)
    def get_result(self):
        try:
            return self.result
        except Exception:
            return []


def url_title(url):
    """
    url: 必须带https或http前缀
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/87.0.4280.77 Mobile/15E148 Safari/604.1 Edg/100.0.4896.127'}
    result = {'title': '', 'code': ''}
    url = "http://" + url
    try:
        req = requests.get(url, headers=headers, timeout=2, verify=False)
        result["code"] = req.status_code
    except Exception as e:
        logger.error(f"[+]{url}, http请求获取title失败！")
        return result
    try:
        req.encoding = req.apparent_encoding
        result["title"] = BS(req.text, 'lxml').title.text.strip()
    except:
        result["title"] = ''
    return result


def ip2domain(ip):
    domain_results = []
    threads = []
    for fun in [webscan, rapiddnsio, ip138, ipchaxun, aizhan, dnsgrep, viewdns, virustotal]:
        t = MyThread(fun, args=(ip,), name=fun.__name__)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
        if t.exit_code != 0:
            logger.info("[+]" + t.getName() + ":failure," + t.exception.__str__())
        # else:
            # logger.info("[+]" + t.getName() + ":success")
        domain_results.extend(t.get_result())
    return domain_results


if __name__ == '__main__':
    # 测试单个接口
    # print(ip138('103.41.167.234'))
    from argparse import RawTextHelpFormatter
    # 配置自己的virustotal key
    default_vt_key = ''
    def cmd_run(result):
        with open("result.csv", 'w', newline='', encoding='gbk') as f:
            header = result[0].keys()
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(result)
        logger.info("Success！Result：result.csv")
    parser = argparse.ArgumentParser(description="""
     _/_/_/  _/_/_/  _/_/_/    
  _/          _/    _/    _/ 
 _/  _/_/    _/    _/_/_/      
_/    _/    _/    _/           
 _/_/_/  _/_/_/  _/    集合多个接口的IP反查域名工具。注意：使用virustotal接口需配置Key！
API：webscan, rapiddnsio, ip138, ipchaxun, aizhan, dnsgrep, viewdns, virustotal
""", formatter_class=RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', "--ip", help="指定单个IP")
    group.add_argument('-f', "--file", help="从文件批量IP")
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    if args.ip:
        result = ip2domain(args.ip)
        cmd_run(result)
    elif args.file:
        many_result = []
        with open(args.file, 'r', encoding='gbk') as f:
            lines = f.readlines()
            for i in tqdm(range(len(lines))):
                ip = lines[0]
                logger.info(f"[+]从文件读取IP：{ip.strip()}")
                target = ip.strip()
                many_result.extend(ip2domain(target))
        cmd_run(many_result)
