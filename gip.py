#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ip 反查域名工具
# version: 2.2
# update: 2023.4.18
import re, time, sys, csv, json
import argparse
import requests
import urllib3
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
FORMAT = '[%(asctime)-15s] [%(levelname)s] [%(filename)s %(levelno)s line] %(message)s'
logger = logging.getLogger(__file__)
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)
# 结果样例
'''
[{'source': 'ip138', 'ip': '121.4.69.24', 'domain': 'imortal.icu',date: '2020-1-1'}]
'''
class Gip:
    def __init__(self, ip=None, key=None, user_agent=None):
        self.ip = ip
        self.api_key = key
        if user_agent:
            self.user_agent= user_agent
        else:
            self.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15"
    def url_title(self, url):
        result = {'title': '', 'code': ''}
        headers = {'User-Agent': self.user_agent}
        try:
            req = requests.get("https://" + url, headers=headers, timeout=2, verify=False)
            result["code"] = req.status_code
            req.encoding = req.apparent_encoding
            result["title"] = re.findall(r"<title.*?>(.+?)</title>", req.text)[0]
        except Exception as e:
            try:
                req = requests.get("http://" + url, headers=headers, timeout=2, verify=False)
                result["code"] = req.status_code
                req.encoding = req.apparent_encoding
                result["title"] = re.findall(r"<title.*?>(.+?)</title>", req.text)[0]
            except Exception as e:
                logger.error(f"[+]{url}, http请求获取title失败！,{e}")
        return result
    def webscan(self):
        domain_list = []
        url = r'http://api.webscan.cc/?action=query&ip={}'.format(self.ip)
        headers = {'Use-Agent': self.user_agent, 'Referer': url}
        res = requests.get(url=url, headers=headers, timeout=10, verify=False)
        results = json.loads(res.text)
        count = 0
        for domain in results:
            if count < 20:
                data = {"source": 'aizhan', "ip": self.ip, "domain": domain["domain"], "date": ''}
                data.update(self.url_title(domain["domain"]))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def rapiddnsio(self):
        domain_list = []
        session = requests.session()
        resp = session.get("https://rapiddns.io/s/%s#result" % self.ip)
        # df = pd.read_html(html.content)[0].iterrows()
        table_pattern = re.compile(r'<table[^>]*>(.*?)</table>', re.DOTALL)
        row_pattern = re.compile(r'<tr[^>]*>(.*?)</tr>', re.DOTALL)
        cell_pattern = re.compile(r'<td[^>]*>(.*?)</td>', re.DOTALL)
        link_pattern = re.compile(r'<a[^>]*>(.*?)</a>', re.DOTALL)
        # 在 HTML 内容中查找表格
        table_match = table_pattern.search(resp.text)
        # 在表格中查找所有行
        rows_match = row_pattern.findall(table_match.group(1))
        # 将每一行的数据转换为字典
        table_data = []
        for row_match in rows_match:
            # 在行中查找所有单元格
            cells_match = cell_pattern.findall(row_match)
            if not cells_match:
                continue
            # 提取单元格数据，并将数据转换为字典
            row_data = {
                'Domain': cells_match[0],
                'Address': link_pattern.search(cells_match[1]).group(1),
                'Type': cells_match[2],
                'Date': cells_match[3],
            }
            table_data.append(row_data)
        count = 0
        for row in table_data:
            if count < 100:
                data = {'source': 'rapiddns.io', 'ip': self.ip, 'domain': row["Domain"], 'date': row["Date"]}
                data.update(self.url_title(row["Domain"]))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def ip138(self):
        domain_list = []
        headers = {'User-Agent': self.user_agent}
        domain_re = re.compile(r'class="date">(.*?)</span><a href="/(.*?)/"')
        url = 'https://site.ip138.com/' + self.ip
        req = requests.get(url, headers=headers, timeout=3)
        domains = domain_re.findall(req.text)
        count = 0
        for domain in domains:
            if count < 20:
                data = {"source": 'ip138', "ip": self.ip, "domain": domain[1], "date": domain[0]}
                data.update(self.url_title(domain[1]))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def ipchaxun(self):
        domain_list = []
        url = 'https://ipchaxun.com/' + self.ip
        headers = {'User-Agent': self.user_agent}
        domain_re = re.compile(r'class="date">(.*?)</span>\s<a href="/(.*?)/"')
        req = requests.get(url, headers=headers, timeout=3)
        domains = domain_re.findall(req.text)
        count = 0
        for domain in domains:
            if count < 20:
                data = {"source": 'ipchaxun', "ip": self.ip, "domain": domain[1], "date": domain[0]}
                data.update(self.url_title(domain[1]))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def dnsgrep(self):
        domain_list = []
        domain_re = re.compile(r'<tr>[\s\S]*?<td data="(.*?)">[\s\S]*?class="date">(.*?)</td>')
        url = 'https://www.dnsgrep.cn/ip/' + self.ip
        req = requests.get(url, timeout=5)
        domains = domain_re.findall(req.text)
        count = 0
        for i in domains:
            if count < 20:
                data = {"source": 'dnsgrep', "ip": self.ip, "domain": i[0], "date": i[1]}
                data.update(self.url_title(i[0]))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def aizhan(self):
        domain_list = []
        url = f'https://dns.aizhan.com/{self.ip}/'
        headers = {'Use-Agent': self.user_agent, 'Referer': url}
        res = requests.get(url=url, headers=headers, timeout=5, verify=False)
        regx = r'" rel="nofollow" target="_blank">(.*?)</a>'
        results = re.findall(regx, res.text)
        count = 0
        for domain in results:
            if count < 20:
                data = {"source": 'aizhan', "ip": self.ip, "domain": domain, "date": ''}
                data.update(self.url_title(domain))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def viewdns(self):
        domain_list = []
        url = f'https://viewdns.info/reverseip/?host={self.ip}&t=1'
        headers = {'user-agent': self.user_agent, 'referer': "https://viewdns.info/"}
        res = requests.get(url=url, headers=headers, timeout=10, verify=False)
        regx = r'<tr> <td>(.*?)</td><td align="center">(.*?)</td></tr>'
        results = re.findall(regx, res.text)
        count = 0
        for i in results:
            if count < 100:
                data = {"source": 'viewdns', "ip": self.ip, "domain": i[0], "date": i[1]}
                data.update(self.url_title(i[0]))
                domain_list.append(data)
                count = count + 1
        return domain_list

    def virustotal(self):
        domain_list = []
        virustotal_api_key = self.api_key["virustotal"]["api_key"]
        if not virustotal_api_key:
            logger.warning("请配置Virustotal API KEY！！！")
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{self.ip}/resolutions'
        headers = {
            'user-agent': self.user_agent,
            'x-apikey': virustotal_api_key
        }
        res = requests.get(url=url, headers=headers, timeout=10, verify=False)
        count = 0
        for i in json.loads(res.text)['data']:
            if count < 20:
                domain = i['attributes']['host_name']
                date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i['attributes']['date']))
                data = {"source": 'virustotal', "ip": self.ip, "domain": domain, "date": date}
                data.update(self.url_title(domain))
                domain_list.append(data)
                count = count + 1
        return domain_list


    def dnslytics(self,cookie=None):
        # 需要cookie
        domain_list = []
        url = 'https://dnslytics.com/reverse-ip'
        cookie = '_ga=GA1.2.869800091.1681779672; _gid=GA1.2.770523962.1681779672; _gat=1; cf_clearance=k.ZJqp4GrC1Ho1rKcbkVivus3pbaUE4Qz1iIvxKrJnk-1681779664-0-250'
        data = {'reverseip': self.ip}
        headers = {'User-Agent': self.user_agent, "Referer": url, 'Cookie': cookie}
        req = requests.post(url, data=data, headers=headers, timeout=10)
        domain_re = re.compile(r'name="whois" value="(.*?)"><input class="')
        domains = domain_re.findall(req.text)
        count = 0
        for domain in domains:
            if count < 20:
                data = {"source": 'dnslytics', "ip": self.ip, "domain": domain}
                data.update(self.url_title(domain))
                domain_list.append(data)
                count = count + 1
        return domain_list

    def mian(self):
        result = []
        api_list = [self.webscan, self.rapiddnsio, self.ip138, self.ipchaxun, self.aizhan, self.dnsgrep, self.viewdns, self.virustotal]
        with ThreadPoolExecutor() as pool:
            futures = {}
            for api in api_list:
                future = pool.submit(api)
                futures[future] = [self.ip, api.__name__]
        for future in futures:
            if future.exception():
                logger.error(f'[+]Query IP {futures[future][0]} failure use {futures[future][1]},error log is {future.exception().__str__()}')
            else:
                result.extend(future.result())
        return result


if __name__ == '__main__':
    # 配置api key
    api_key = {
        "virustotal": {"api_key": ""},
        "xxx": {"api_key": ""}
    }
    # a = Gip(ip="103.41.167.234", key=api_key)
    # print(a.virustotal())
    from argparse import RawTextHelpFormatter
    def cmd_run(result):
        with open("result.csv", 'w', newline='', encoding='utf-8') as f:
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
        result = Gip(args.ip, key=api_key).mian()
        cmd_run(result)
    elif args.file:
        many_result = []
        with open(args.file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for i in tqdm(range(len(lines))):
                ip = lines[0]
                logger.info(f"[+]从文件读取IP：{ip.strip()}")
                target = ip.strip()
                many_result.extend(Gip(target, key=api_key).mian())
        cmd_run(many_result)
