import sys, json, configparser, os
from ..call_api import Config, ShadowAPI
from ..resources import ReportTypes
from pprint import pprint
from datetime import date
from time import sleep

config = json.loads(open("shadowapi/tests/conf.json", 'r').read())
c = Config(**config)
S = ShadowAPI(c)

# NOTE: We need sleeps because of IP Blocking for rate limiting
def test_connection():
    r = S.ping()
    assert r['pong'] != None

    r = S.keyinfo()
    assert r[0]['user'] != None
    sleep(1)

def test_reports():
    r = S.report_subscribed()
    assert r != None

    r = S.report_types()
    print(type(r))
    assert type(r) in (dict, list)
    SUBSCRIBED_REPORT_TYPES = r.copy()

    r = S.report_stats(report = "united-states", type_=r[0])
    assert type(r) in (dict, list)
    sleep(1)

    r = S.report_list(reports = ["united-states"], limit = 3)
    assert type(r) in (dict, list)
    sleep(1)
    
    r = S.report_list(
        reports = ["united-states", "california"], 
        type_ = "hp_ics_scan", date_ = date(2020, 10, 27)
    )
    assert type(r) in (dict, list)
    
    r = S.report_download(
        id_ = "uN6n7yZK90sdflkjdlLKTOkspksg?HjgX1lI_hAdsKGmVanG_Og", 
        limit = 3
    )
    assert type(r) in (dict, list)

    r = S.report_download(
       report = "california", date_ = date(2020, 10, 26), 
       type_ = "scan_ssl_freak", limit = 1
    )
    assert type(r) in (dict, list)

    r = S.report_query(date_ = date(2020, 10, 27), 
        query = {"geo":"us", "port":443}, limit =1
    )
    assert type(r) in (dict, list)
    sleep(1)

def test_malware():
    r = S.malware(["dfe1832e02888422f48d6896dc8e8f73"])
    assert type(r) in (dict, list)

    r = S.trusted_program("dfe1832e02888422f48d6896dc8e8f73")
    assert type(r) in (dict, list)
    sleep(1)

def test_network():
    r = S.network(peer = "8.8.8.8")
    assert type(r) in (dict, list)

    r = S.network(peer = [ "8.8.8.8", "8.8.4.4" ])
    assert type(r) in (dict, list)

    r = S.network(origin = "8.8.8.8")
    assert type(r) in (dict, list)
    sleep(1)

    r = S.network(origin = [ "8.8.8.8", "8.8.4.4" ])
    assert type(r) in (dict, list)

    r = S.network(prefix = 22414)
    assert type(r) in (dict, list)

    r = S.network(query = 109)
    assert type(r) in (dict, list)
    sleep(1)

def test_ssl():
    r = S.ssl({"port":443}, limit=1, date_=date(2020, 12, 21))
    assert type(r) in (dict, list)
    sleep(1)