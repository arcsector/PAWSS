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
    subsc = S.report_subscribed()
    assert type(subsc) is list 

    types = S.report_types()
    assert type(types) is list

    stats = S.report_stats(date_=date_since, date_end=date_today)
    assert type(stats) is list
    sleep(1)

    report_list = S.report_list(date_=date_since, date_end=date_today, limit=10)
    assert type(report_list) is list
    
    down = S.report_download(id_ = report_list[0]['id'], limit = 3)
    assert type(down) in (dict, list)

    query = S.report_query(query = {'type': 'scan'}, date_=date_since, date_end=date_today, limit=10)
    assert type(query) in (dict, list)
    sleep(1)

def test_malware(S: ShadowAPI):
    r = S.malware(["dfe1832e02888422f48d6896dc8e8f73"])
    assert type(r) in (dict, list)

    r = S.trusted_program("dfe1832e02888422f48d6896dc8e8f73")
    assert type(r) in (dict, list)
    sleep(1)

def test_network(S: ShadowAPI):
    r = S.network(peer = "***REMOVED***")
    assert type(r) in (dict, list)

    r = S.network(peer = [ "***REMOVED***", "***REMOVED***" ])
    assert type(r) in (dict, list)

    r = S.network(origin = "***REMOVED***")
    assert type(r) in (dict, list)
    sleep(1)

    r = S.network(origin = [ "***REMOVED***", "***REMOVED***" ])
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

def test_asn(S: ShadowAPI):
    r1 = S.asn(peer = "***REMOVED***")
    assert type(r1) in (dict, list)

    r2 = S.asn(peer = [ "***REMOVED***", "***REMOVED***" ])
    assert type(r2) in (dict, list)

    r3 = S.asn(origin = "***REMOVED***")
    assert type(r3) in (dict, list)
    sleep(1)

    r4 = S.asn(origin = [ "***REMOVED***", "***REMOVED***" ])
    assert type(r4) in (dict, list)

    r5 = S.asn(prefix = 22414)
    assert type(r5) in (dict, list)

    r6 = S.asn(query = 109)
    assert type(r6) in (dict, list)
    sleep(1)

def test_honeypot(S: ShadowAPI, date_since: date, date_today: date):
    # Test honeypot common vulnerabilities
    r1 = S.honeypot_common_vulnerabilities(date_=date_since, date_end=date_today, limit=10)
    assert type(r1) in (dict, list)
    sleep(1)

    # Test honeypot exploited vulnerabilities
    r2 = S.honeypot_exploited_vulnerabilities(limit=10)
    assert type(r2) in (dict, list)

    # Test with IoT filter
    r3 = S.honeypot_exploited_vulnerabilities(iot="yes", limit=5)
    assert type(r3) in (dict, list)
    sleep(1)

    # Test with KEV filter
    r4 = S.honeypot_exploited_vulnerabilities(kev="yes", limit=5)
    assert type(r4) in (dict, list)

    # Test with geo filter
    r5 = S.honeypot_exploited_vulnerabilities(geo=["US"], limit=5)
    assert type(r5) in (dict, list)
    sleep(1)

    # Test honeypot vulnerability count
    r6 = S.honeypot_vulnerability_count(host_type="dst", vulnerability="CVE-2017-17215", limit=10)
    assert type(r6) in (dict, list)

    # Test with vendor filter
    r7 = S.honeypot_vulnerability_count(vendor="Huawei", limit=10)
    assert type(r7) in (dict, list)
    sleep(1)

    # Test with geo filter
    r8 = S.honeypot_vulnerability_count(geo=["DE", "US"], limit=10)
    assert type(r8) in (dict, list)
    sleep(1)
