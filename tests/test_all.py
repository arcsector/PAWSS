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

    down = S.report_download(id_ = report_list[0]['id'])
    assert type(down) in (dict, list)

    query = S.report_query(query = {'type': 'scan_http'}, date_=date_since, date_end=date_today, limit=10)
    assert type(query) in (dict, list)
    sleep(1)

    # Test report device-info (requires valid IP from organization's filter)
    # Note: This test requires query to match organization's report filters
    # Uncomment and adjust IP/ASN/geo to match your organization:
    # r_device = S.report_device_info({"ip": "192.168.1.1", "geo": "US"})
    # assert type(r_device) is dict
    # sleep(1)

    # Test report schema
    if len(types) > 0:
        schema = S.report_schema(types[0])
        assert type(schema) is dict
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

def test_asn(S: ShadowAPI):
    r1 = S.asn(peer = "8.8.8.8")
    assert type(r1) in (dict, list)

    r2 = S.asn(peer = [ "8.8.8.8", "8.8.4.4" ])
    assert type(r2) in (dict, list)

    r3 = S.asn(origin = "8.8.8.8")
    assert type(r3) in (dict, list)
    sleep(1)

    r4 = S.asn(origin = [ "8.8.8.8", "8.8.4.4" ])
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
    
    # Test honeypot exploited vulnerabilities
    r2 = S.honeypot_exploited_vulnerabilities(limit=10)
    assert type(r2) in (dict, list)

    # Test with IoT filter
    r3 = S.honeypot_exploited_vulnerabilities(iot="yes", limit=5)
    assert type(r3) in (dict, list)
    
    # Test with KEV filter
    r4 = S.honeypot_exploited_vulnerabilities(kev="yes", limit=5)
    assert type(r4) in (dict, list)

    # Test with geo filter
    r5 = S.honeypot_exploited_vulnerabilities(geo=["US"], limit=5)
    assert type(r5) in (dict, list)
    
    # Test honeypot vulnerability count
    r6 = S.honeypot_vulnerability_count(host_type="dst", vulnerability="CVE-2017-17215", limit=10)
    assert type(r6) in (dict, list)

    # Test with vendor filter
    r7 = S.honeypot_vulnerability_count(vendor="Huawei", limit=10)
    assert type(r7) in (dict, list)
    
    # Test with geo filter
    r8 = S.honeypot_vulnerability_count(geo=["DE", "US"], limit=10)
    assert type(r8) in (dict, list)
    sleep(1)

def test_scan(S: ShadowAPI, date_since: date, date_today: date):
    # Test scan network - get CIDR blocks
    r1 = S.scan_network()
    assert type(r1) is list
    assert len(r1) > 0

    # Test scan CVE list
    r2 = S.scan_cve_list()
    assert type(r2) is list
    assert len(r2) > 0

    r3 = S.scan_ssl({"port":443}, limit=1, date_=date_since, date_end=date_today)
    assert type(r3) in (dict, list)
    sleep(1)

    # Note: scan_target_update requires special authorization and modifies data
    # so it's not included in regular tests. Test only if authorized:
    # r3 = S.scan_target_update("www.example.com mail.example.com")
    # assert type(r3) is dict
    # assert "accepted" in r3

def test_filters(S: ShadowAPI):
    # Test filters CIDR contents
    r1 = S.filters_cidr_contents()
    assert type(r1) is dict
    sleep(1)

    # Test filters RHost contents
    r2 = S.filters_rhost_contents()
    assert type(r2) is dict
    sleep(1)

    # Note: The following update methods modify data and require special authorization.
    # They are commented out for regular tests but can be enabled with proper credentials:

    # Test CIDR update with dry-run
    # r3 = S.filters_cidr_update("192.168.100.1/32\n192.168.103.6/32", dry_run=True)
    # assert type(r3) is dict
    # assert "accepted" in r3
    # sleep(1)

    # Test RHost update with dry-run
    # r4 = S.filters_rhost_update("com.example.\nnet.example.", dry_run=True)
    # assert type(r4) is dict
    # assert "accepted" in r4
    # sleep(1)
