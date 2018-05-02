#!/usr/bin/env python
import time
import requests
import sys
import hashlib
from time import sleep
from bs4 import BeautifulSoup
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CollectorRegistry

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

    r = requests.get(
        'http://{host}/data/Login.json?_time={time}&_rand=666&csrf_token={csrf}'
        .format(host=target_ip, time=time_ms, csrf=init_csrf))

    data = r.json()

    return get_json_value(data, "challenge")


def gen_passwd(password, challenge):
    # Create a sha256 sum of the password+challenge
    return hashlib.sha256(password.encode() + challenge.encode()).hexdigest()


def login(target_ip, hashed_pw):
    # Send a post request to the Login.json which contains the hashed_pw
    # and the static csrf token
    r = requests.post("http://{}/data/Login.json?lang=de".format(target_ip),
                      data={
                        'password': hashed_pw,
                        'showpw': 0,
                        'csrf_token': init_csrf})
    if get_json_value(r.json(), "login") != "success":
        print("login failed")
        return None
    return r.cookies


def parse_dsl_info(info_string):
    soup = BeautifulSoup(info_string, 'html.parser')

    dsl_params = {}
    for item in soup.find_all('tr'):
        vals = []
        for td in item.find_all('td'):
            vals.append(td.string)
        # At the beginning one long list contains all values, after that there
        # is a list for every parameter, therefore check for
        # a valid list length (2 and 3 are valid)
        if vals[0] != "Parameters" and len(vals) > 1 and len(vals) < 4:
            field = vals[0].replace(" ", "")
            if len(vals) == 2:
                dsl_params[field] = vals[1]
            elif len(vals) == 3:
                dsl_params["u" + field] = vals[1]
                dsl_params["d" + field] = vals[2]
    return dsl_params


def parse_metric_info(info_string):
    soup = BeautifulSoup(info_string, 'html.parser')

    dsl_params = {}
    for item in soup.find_all('tr'):
        vals = []
        for td in item.find_all('td'):
            vals.append(td.string)
        # At the beginning one long list contains all values, after that there
        # is a list for every parameter, therefore check for
        # a valid list length (2 and 3 are valid)
        if vals[0] != "Parameters" and len(vals) > 1 and len(vals) < 4:
            field = vals[0].replace(" ", "")
            if len(vals) == 2:
                dsl_params[field] = vals[1]
            elif len(vals) == 3:
                dsl_params[field] = (vals[1], vals[2])  # Upload, Download
    return dsl_params


def to_float(input_str):
    try:
        return float(input_str.split()[0])  # metrics have unit at last
    except ValueError:
        return 0


class SpeedportCollector(object):
    def collect(self):
        # The pages in the engineer mode don't need a csrf_token, other requests do
        # however need it. A valid token can be extracted from the index.html
        dsl_info = requests.get("http://{}/html/engineer/ro_dsl.htm"
                                .format(sys.argv[1]), cookies=cookie_jar)
        ds = parse_metric_info(dsl_info.text)
        # Dirty approach to DSL metrics, only gauge is available
        # because we can only scrape error counts, not increment them
        speedport_state = GaugeMetricFamily('speedport_state', 'DSL Sync state', labels=["host", "report"])  # State; 1=online, 0=anything else
        speedport_state.add_metric([sys.argv[1], ds["State"]], 1 if ds["State"] == "online" else 0)
        yield speedport_state
        speedport_actual_data_rate = GaugeMetricFamily('speedport_actual_data_rate_kpbs', 'Actual DSL Sync data rate', labels=["host", "method"])  # ActualDataRate
        speedport_actual_data_rate.add_metric([sys.argv[1], "upload"], to_float(ds["ActualDataRate"][0]))
        speedport_actual_data_rate.add_metric([sys.argv[1], "download"], to_float(ds["ActualDataRate"][1]))
        yield speedport_actual_data_rate
        speedport_attainable_data_rate = GaugeMetricFamily('speedport_attainable_data_rate_kpbs', 'Attainable DSL Sync data rate', labels=["host", "method"])  # AttainableDataRate
        speedport_attainable_data_rate.add_metric([sys.argv[1], "upload"], to_float(ds["AttainableDataRate"][0]))
        speedport_attainable_data_rate.add_metric([sys.argv[1], "download"], to_float(ds["AttainableDataRate"][1]))
        yield speedport_attainable_data_rate
        speedport_crc = GaugeMetricFamily('speedport_crc_error_count', 'Amount of CRC Errors', labels=["host", "method"])  # CRCerrorcount
        speedport_crc.add_metric([sys.argv[1], "upload"], to_float(ds["CRCerrorcount"][0]))
        speedport_crc.add_metric([sys.argv[1], "download"], to_float(ds["CRCerrorcount"][1]))
        yield speedport_crc
        speedport_fec = GaugeMetricFamily('speedport_fec_error_count', 'Amount of FEC Errors', labels=["host", "method"])  # FECerrorcount
        speedport_fec.add_metric([sys.argv[1], "upload"], to_float(ds["FECerrorcount"][0]))
        speedport_fec.add_metric([sys.argv[1], "download"], to_float(ds["FECerrorcount"][1]))
        yield speedport_fec
        speedport_hec = GaugeMetricFamily('speedport_hec_error_count', 'Amount of HEC Errors', labels=["host", "method"])  # HECerrorcount
        speedport_hec.add_metric([sys.argv[1], "upload"], to_float(ds["HECerrorcount"][0]))
        speedport_hec.add_metric([sys.argv[1], "download"], to_float(ds["HECerrorcount"][1]))
        yield speedport_hec
        speedport_line_attenuation = GaugeMetricFamily('speedport_line_attenuation', 'Line Attenuation', labels=["host", "method"])  # LineAttenuation
        speedport_line_attenuation.add_metric([sys.argv[1], "upload"], to_float(ds["LineAttenuation"][0]))
        speedport_line_attenuation.add_metric([sys.argv[1], "download"], to_float(ds["LineAttenuation"][1]))
        yield speedport_line_attenuation
        speedport_snr = GaugeMetricFamily('speedport_snr_margin', 'SNR Margin', labels=["host", "method"])  # SNRMargin
        speedport_snr.add_metric([sys.argv[1], "upload"], to_float(ds["SNRMargin"][0]))
        speedport_snr.add_metric([sys.argv[1], "download"], to_float(ds["SNRMargin"][1]))
        yield speedport_snr
        speedport_signal_level = GaugeMetricFamily('speedport_signal_level', 'Signal Level', labels=["host", "method"])  # Signal-level
        speedport_signal_level.add_metric([sys.argv[1], "upload"], to_float(ds["Signal-level"][0]))
        speedport_signal_level.add_metric([sys.argv[1], "download"], to_float(ds["Signal-level"][1]))
        yield speedport_signal_level


if len(sys.argv) != 3:
    print("Usage: {} [ip] [password]".format(sys.argv[0]))
    sys.exit(1)

challenge = get_challenge(sys.argv[1])
hashpw = gen_passwd(sys.argv[2], challenge)
cookie_jar = login(sys.argv[1], hashpw)

if cookie_jar is None:
    sys.exit(1)

registry = CollectorRegistry()
registry.register(SpeedportCollector())

start_http_server(8000, registry=registry)

while True:
    sleep(60)  # Run as a deamon and serve metrics
