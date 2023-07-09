#!/usr/bin/ python
# -*- coding:utf-8 -*-
"""
-------------------------------------------------
Author:       loecho
Datetime:     2021-07-23 12:47
ProjectName:  getFinger.py
Blog:         https://loecho.me
Email:        loecho@foxmail.com
-------------------------------------------------
"""
import sys
import json
import requests
import socket
import os
import ast
import re

requests.packages.urllib3.disable_warnings()


'''
-----ARL支持字段：-------
body = " "
title = ""
header = ""
icon_hash = ""
'''



def main(url, token):
    
    f11 = open("/tmp/finger.json",'r', encoding="utf-8")
    content =f11.read()
    pattern_cms = r'"cms":\s*"([^"]+)"'
    pattern_keyword = r'"keyword":\s*"([^"]+)"'
    pattern_location = r'"location":\s*"([^"]+)"'
    pattern_method = r'"method":\s*"([^"]+)"'
    
    matches_cms = re.findall(pattern_cms, content)
    matches_keyword = re.findall(pattern_keyword, content)
    matches_location = re.findall(pattern_location, content)
    matches_method = re.findall(pattern_method, content)
    cms_values = []
    keyword_values = []
    location_values = []
    method_values = []
    for match in matches_cms:
        cms_values.append(match)
    for match in matches_keyword:
        keyword_values.append(match)
    for match in matches_location:
        location_values.append(match)
    for match in matches_method:
        method_values.append(match)
    print(len(method_values))
    print(method_values[0])
    for i in range(0, len(method_values)-1):
        try:
            if method_values[i] == "keyword" and location_values[i] == "body":
                name = cms_values[i]
                rule = keyword_values[i]
                add_Finger(name, rule, url, token)
            elif method_values[i] == "keyword" and location_values[i] == "title":
                name = cms_values[i]
                rule = keyword_values[i]
                add_Finger(name, rule, url, token)
            elif method_values[i] == "faviconhash" and location_values[i] == "body":
                name = cms_values[i]
                rule = keyword_values[i]
                add_Finger(name, rule, url, token)
            elif method_values[i] == "keyword" and location_values[i] == "header":
                name = cms_values[i]
                rule = keyword_values[i]
                add_Finger(name, rule, url, token)
        except IndexError:
            pass

def add_Finger(name, rule, url, token):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
        "Connection": "close",
        "Token": "{}".format(token),
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json; charset=UTF-8"
    }
    url = "{}/api/fingerprint/".format(url)
    data = {"name" : name,"human_rule": rule}
    data_json = json.dumps(data)

    try:
        response = requests.post(url, data=data_json, headers=headers, verify=False)
        if response.status_code == 200:
            print(''' Add: [\033[32;1m+\033[0m]  {}\n Rsp: [\033[32;1m+\033[0m] {}'''.format(data_json, response.text))
    except Exception as e:
        print(e)


def test(name,rule):

    return print("name: {}, rule: {}".format(name, rule))



if __name__ == '__main__':
    try:
        if len(sys.argv)<99999999 :
            
            # 获取主机名
            hostname = socket.gethostname()

            # 获取 IP 地址
            ip_address = socket.gethostbyname(hostname)

            # 拼接 URL
            url22 = f"https://{ip_address}:5003/"
            login_url = sys.argv[1] if len(sys.argv) > 1 else url22
            login_name = sys.argv[2] if len(sys.argv) > 2 else "admin"
            login_password = sys.argv[3] if len(sys.argv) > 3 else "arlpass"

            # login
            str_data = {"username": login_name, "password": login_password}
            login_data = json.dumps(str_data)
            login_res = requests.post(url="{}api/user/login".format(login_url), headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
                "Content-Type": "application/json; charset=UTF-8"}, data=login_data, verify=False)

            # 判断是否登陆成功：
            if "401" not in login_res.text:

                #print(type(login_res.text))
                token = json.loads(login_res.text)['data']['token']
		print("token："+str(token))
                print("[+] Login Success!!")

                # main
                main(login_url,token)
            else:
                print("[-] login Failure! ")
        else:
            print('''
    usage:
        
        python3 ARl-Finger-ADD.py https://192.168.1.1:5003/ admin password
                                                        
                                                         by  loecho
            ''')
    except Exception as a:
        print(a)
