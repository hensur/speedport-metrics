#!/usr/bin/env python
import time
import requests
import sys
import hashlib
from html.parser import HTMLParser
from bs4 import BeautifulSoup
from pprint import pprint

# arg1: router ip
# arg2: pw

init_csrf = "sercomm_csrf_token"

def get_json_value(data, id):
    for item in data:
        if item["varid"] == id:
            return item["varvalue"]
    return None

def get_challenge(target_ip):
    # get the challenge to authenticate against the SpeedportEntry2
    time_ms = round(time.time() * 1000)

    r = requests.get('http://{host}/data/Login.json?_time={time}&_rand=666&csrf_token={csrf}'.format(host=target_ip, time=time_ms, csrf=init_csrf))

    data = r.json()

    return get_json_value(data, "challenge")

def gen_passwd(password, challenge):
    return hashlib.sha256(password.encode() + challenge.encode()).hexdigest()

def login(target_ip, hashed_pw):
    r = requests.post("http://{}/data/Login.json?lang=de".format(target_ip), data={'password': hashed_pw, 'showpw': 0, 'csrf_token': init_csrf})
    if get_json_value(r.json(), "login") == "success":
        print ("login success")
    else:
        print("login failed")
        return None
    return r.cookies

def parse_dsl_info(info_string):
    soup = BeautifulSoup(info_string, 'html.parser')

    dsl_params = {}
    stream_params = {}
    for item in soup.find_all('tr'):
        vals = []
        for td in item.find_all('td'):
            vals.append(td.string)
        if vals[0] != "Parameters":
            if len(vals) == 2:
                dsl_params[vals[0]] = vals[1]
            elif len(vals) == 3:
                stream_params[vals[0]] = (vals[1], vals[2])

    return (dsl_params, stream_params)

if len(sys.argv) != 3:
    print("Usage: {} [ip] [password]".format(sys.argv[0]))
    sys.exit(1)

challenge = get_challenge(sys.argv[1])
hashpw = gen_passwd(sys.argv[2], challenge)
cookie_jar = login(sys.argv[1], hashpw)

if cookie_jar == None:
    sys.exit(1)
dsl_info = requests.get("http://{}/html/engineer/ro_dsl.htm".format(sys.argv[1]), cookies=cookie_jar)
ds, st = parse_dsl_info(dsl_info.text)

print("DSL Status:")
pprint(ds)
print("DSL Values:")
pprint(st)