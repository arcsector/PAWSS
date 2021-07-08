from shadowapi.call_api import ShadowAPI
from datetime import date
from time import sleep
import pytest

# NOTE: We need sleeps because of IP Blocking for rate limiting
def test_connection(S):
    r = S.ping()
    assert r['pong'] != None

    r = S.keyinfo()
    assert r[0]['user'] != None
    sleep(1)

def test_reports(S: ShadowAPI, date_since: date, date_today: date):
    r = S.report_subscribed()
    assert type(r) == list 

    r = S.report_types()
    assert type(r) == list

    stats = S.report_stats(date_=date_since, date_end=date_today)
    assert type(stats) == list
    sleep(1)

    report_list = S.report_list(date_=date_since, date_end=date_today, limit=10)
    assert type(report_list) == list
    
    r = S.report_download(id_ = report_list[0]['id'], limit = 3)
    assert type(r) in (dict, list)

    r = S.report_query(query = {'geo': 'us'}, date_=date_since, date_end=date_today, limit=10)
    assert type(r) in (dict, list)
    sleep(1)

def test_malware(S: ShadowAPI):
    r = S.malware(["dfe1832e02888422f48d6896dc8e8f73"])
    assert type(r) in (dict, list)

    r = S.trusted_program("dfe1832e02888422f48d6896dc8e8f73")
    assert type(r) in (dict, list)
    sleep(1)

def test_network(S: ShadowAPI):
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

def test_ssl(S: ShadowAPI, date_since: date, date_today: date):
    r = S.ssl({"port":443}, limit=1, date_=date_since, date_end=date_today)
    assert type(r) in (dict, list)
    sleep(1)