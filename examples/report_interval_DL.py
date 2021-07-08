from shadowapi import Config, ShadowAPI
from shadowapi import ReportTypes, QueryFilters, SSLQuery
from pprint import pprint
from datetime import date, timedelta

config = {
    "key": "AAA-AAA",
    "secret": "BBB-CCC",
    "uri": "https://transform.shadowserver.org/api2/"
}

if __name__ == '__main__':
    c = Config(**config)
    S = ShadowAPI(c)
    date_since = date.today() - timedelta(days=7)
    date_today = date.today()

    report_list = S.report_list(date_=date_since, date_end=date_today, limit = 3)
    print(len(report_list))

    for short in report_list:
        id_ = short['id']
        r = S.report_download(id_=id_)
        pprint(r)
