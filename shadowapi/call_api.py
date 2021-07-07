#!/usr/bin/env python3
import hmac
import hashlib
import json
import requests
from datetime import date

from .resources import QueryFilters, SSLQuery, ReportTypes

class Config:
    """Class for Config variables

    Normally housed in a secrets file, but now can be anything modularly passed to this config.
    Is used for authentication to API by :class:`ShadowAPI`.

    Args:
        key (str): API Key
        secret (str): API Secret
        uri (str, optional): URI for shadowserver auth. Defaults to "https://transform.shadowserver.org/api2/".

    Attributes:
        key (str): API Key
        secret (str): API Secret
        uri (str): URI for shadowserver auth. Defaults to "https://transform.shadowserver.org/api2/".
    """
    key: str
    secret: str
    uri: str

    def __init__(self, key: str, secret: str, uri: str = "https://transform.shadowserver.org/api2/"):
        self.key = key
        self.secret = secret
        self.uri = uri

    def to_dict(self) -> dict:
        return {"key": self.key, "secret": self.secret, "uri": self.uri}

class ShadowAPI:
    """Shadowserver API query wrapper main class

    Used to query shadowserver for anything supported by the v2 API

    Args:
        config (:class:`Config`, optional): Configurations for authentication. Defaults to None.
        timeout (int, optional): Timeout length in seconds. Defaults to 45.

    Attributes:
        config (:class:`Config`): Configurations for authentication. Defaults to None.
        TIMEOUT (int): Timeout length in seconds. Defaults to 45.
        base_uri (str): URI for Shadowserver API
        secret_bytes (bytes): Filled when :meth:`api_call` is first ran. Bytestring of API secret
    """
    TIMEOUT: int
    config: Config
    base_uri: str = "https://api.shadowserver.org/"
    secret_bytes: bytes

    def __init__(self, config: Config = None, timeout: int = 45):
        if config:
            self.config = config
        self.TIMEOUT = timeout

    def check_valid(self, dictionary: dict, variable_list: list) -> dict:
        """Set variables which are non-empty into a dictionary

        Args:
            dictionary (dict): Dictionary to set
            variable_list (list): List of variables in tuples with the string name 
                of the variable first and the variable value second

        Returns:
            dict: Modified dictionary
        """
        for tup in variable_list:
            name = tup[0]
            variable = tup[1]
            if variable: dictionary[name] = variable
        return dictionary

    def date_eval(self, date_: date, date_end: date = None) -> str:
        """Creates stringified date range accepted by Shadowserver

        Args:
            date_ (date): Initial date in the past
            date_end (date, optional): Final date which is greater 
                than the initial date. Note if this is not specified,
                it is assumed that all entries from ``date_`` until now
                are requested.

        Returns:
            string: Stringified date with either a date or date range in 
                format ``%Y-%m-%d[:%Y-%m-%d]`` where the bracketed date is
                optional.
        """
        if date: date_ = date_.strftime("%Y-%m-%d")
        if date_end: date_ = date_ + ':' + date_end.strftime("%Y-%m-%d")
        return date_

    def api_call(self, endpoint: str, request: dict = {}) -> list or str:
        """Call the specified api endpoint with a request dictionary.

        Args:
            endpoint (str): HTTP endpoint to call
            request (dict, optional): Request parameters dictionary. 
                Defaults to an empty dictionary.

        Returns:
            list or :class:`Requests.Response`: either returns a 
                serialized JSON list or a Requests Response
        """
        url = self.config.uri + endpoint

        request['apikey'] = self.config.key
        request_string = json.dumps(request)

        # cache secret bytes
        if not hasattr(self, 'secret_bytes'):
            self.secret_bytes = bytes(str(self.config.secret), 'latin-1')

        request_bytes = bytes(request_string, 'latin-1')

        hmac_generator = hmac.new(self.secret_bytes, request_bytes, hashlib.sha256)
        hmac2 = hmac_generator.hexdigest()

        req = requests.session()
        response = req.post(url, data=request_bytes, headers={'HMAC2': hmac2}, timeout=self.TIMEOUT)

        resp = response
        try:
            resp = response.json()
        except:
            resp = response.text
        return resp

    def set_config(self, key: str, secret: str, uri: str = "https://transform.shadowserver.org/api2/") -> None:
        self.config = Config(key, secret, uri)

    def ping(self) -> list or str:
        """Ping the server to check credentials and API connectivity

        Returns:
            dict: dictionary with "pong" key
        """
        return self.api_call('test/ping')

    def keyinfo(self) -> list or str:
        """Check info on user associated with the key

        Returns:
            dict: dictionary with info on user associated with the key
        """
        return self.api_call('key/info')

    def report_subscribed(self) -> list or str:
        """Check subscribed reports

        Returns:
            list: list with names of report subscriptions
        """
        return self.api_call('reports/subscribed')

    def report_types(self) -> list or str:
        """Check all possible report types

        Returns:
            list: list with names of report types
        """
        return self.api_call('reports/types')

    def report_list(self, limit: int = None, type_: str = None, reports: list = None, date_: date = None, date_end: date = None) -> list or str:
        """List all reports

        Args:
            type_ (str): Specific report to get download ID for.
            limit (int): Limit the query to a specific number of records.
            reports (list, optional):  Report types to return. Defaults to None.
            date_ (date, optional): Date to get reports for. Defaults to None.
            date_end (date, optional): Date to get reports since ``date_``; should be 
                later than ``date_``. Defaults to None.

        Returns:
            list: List of reports
        """
        req_dict = {}
        if date_: date_ = self.date_eval(date_, date_end)
        req_dict = self.check_valid(req_dict, 
            [("type", type_), ("limit", limit), ("reports", reports), ("date", date_)]
        )
        return self.api_call('reports/list', req_dict)

    def report_download(self, id_: str = None, report: str = None, limit: int = None, 
        type_: str = None, date_: date = None, date_end: date = None
        ) -> list or str:
        """Downloads details on reports

        Args:
            id_ (str, optional): ID of report. Defaults to None.
            report (str, optional): Name of report. Defaults to None.
            limit (int, optional): Limit on number of reports. Defaults to None.
            date_ (date, optional): Date to search reports for. Defaults to None.
            date_end (date, optional): Date to search reports since ``date_``; should be 
                later than ``date_``. Defaults to None.

        Returns:
            list: List of report JSON
        """
        req_dict = {}
        if date_: date_ = self.date_eval(date_, date_end)
        req_dict = self.check_valid(req_dict, 
            [("id", id_), ("limit", limit), ("report", report), ("date", date_)]
        )
        data = self.api_call("reports/download", req_dict)
        return data

    def report_stats(self, report: str = None, type_: str = None, 
        date_: date = None, date_end: date = None) -> list or str:
        """Allows looking through the history of the statistics of the different reports.

        Args:
            report (Union[str, list]): Report names
            type_ (Union[str, list]): Types of report to get
            date_ (date): Date to get reports with
            date_end (date, optional): Date to get reports with since ``date_``; should be 
                later than ``date_``. Defaults to None.

        Returns:
            list: List of statistics
        """
        req_dict = {}
        if date_: date_ = self.date_eval(date_, date_end)
        req_dict = self.check_valid(req_dict, 
            [("type", type_), ("report", report), ("date", date_)]
        )
        return self.api_call("reports/stats", req_dict)

    def report_query(self, query: dict, limit: int, page: int = 1, sort: str = None, 
        date_: str = None, date_end: date = None, facet: str = None) -> list or str:
        """Queries the report list for reports with specific attributes

        Query must be one of the filters found in :class:`resources.QueryFilters`.
        As a convenience, each filter is listed in both attribute and list format

        Args:
            query (dict): Query to search reports with
            limit (int): [description]
            page (int, optional): [description]. Defaults to 1.
            sort (str, optional): [description]. Defaults to None.
            date_ (date, optional): Date to get reports with
            date_end (date, optional): Date to get reports with since ``date_``; should be 
                later than ``date_``. Defaults to None.
            facet (str, optional): [description]. Defaults to None.

        Returns:
            list: List of reports
        """
        req_dict = {}
        if date_: date_ = self.date_eval(date_, date_end)
        if [q for q in query.keys() if q not in QueryFilters.query_list]:
            raise ValueError("Query was not a valid filter")
        req_dict = self.check_valid(req_dict, [
                ("query", query), ("limit", limit), ("page", page), 
                ("date", date_), ("sort", sort), ("facet", facet)
            ]
        )
        return self.api_call("reports/query", req_dict)

    def malware(self, hashlist: list) -> list or str:
        """Get malware info for a list of hashes

        Args:
            hashlist (list): list of hashes

        Returns:
            list: List of malware info
        """
        return self.api_call("research/malware-info", {"sample": hashlist})
        
    def trusted_program(self, hash_: str) -> list or str:
        """Get program info for a hash

        Args:
            hash_ (str): Hash

        Returns:
            list: Trusted Program info
        """
        return self.api_call("research/trusted-program", {"sample": hash_})

    def network(self, origin: str = None, peer: str = None, prefix: str = None, query: str = None) -> list or str:
        """Get network info on network IoC's

        Args:
            origin (str, optional): IoC as origin ASN. Defaults to None.
            peer (str, optional): IoC as peer ASN. Defaults to None.
            prefix (str, optional): IoC as ASN prefix. Defaults to None.
            query (str, optional): IoC by ASN ID. Defaults to None.

        Returns:
            list or :class:`requests.Response`: JSON data on the IoC
        """
        sess = requests.Session()
        argument = {}
        argument = self.check_valid(argument, 
            [("origin", origin), ("peer", peer), ("prefix", prefix), ("query", query)]
        )
        return self.api_call("research/asn", argument)

    def ssl(self, query: dict, page: int = 1, date_: str = None,
        date_end: date = None, limit: int = None
        ) -> list or str:
        """SSL IoC query

        Args:
            query (dict): Dictionary query parameters to pass
            page (int, optional): Pagination if result set is larger than 1000. Defaults to 1.
            date_ (date, optional): Date to get SSL data from
            date_end (date, optional): Date to get SSL data since ``date_``; should be 
                later than ``date_``. Defaults to None.
            limit (int, optional): IoC return limit. Defaults to None which is 1000.

        Raises:
            ValueError: Raised if Query was not a valid filter for SSL IoCs.

        Returns:
            list or str: IoC data response.
        """
        req_dict = {}
        if date_: date_ = self.date_eval(date_, date_end)
        if [q for q in query.keys() if q not in SSLQuery.ssl_query]:
            raise ValueError("Query was not a valid filter")
        req_dict = self.check_valid(req_dict, 
                [("query", query), ("page", page), ("date", date_), ("limit", limit)]
        )
        return self.api_call("scan/ssl", req_dict)