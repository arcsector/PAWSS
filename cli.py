#!/usr/bin/env python3
"""

call-api.py : Shadowserver Foundation API Utility

This script requires your API details to be stored in ~/.shadowserver.api 
with the following contents:

--
[api]
key = 123456798
secret = MySecret
uri = https://transform.shadowserver.org/api2/
--

This script may be called with two or three arguments:

    call-api.py <method> <request> [pretty|binary]

The request must be a valid JSON object.

Simple usage:

$ ./call-api.py test/ping '{}'
{"pong":"2020-10-26 23:06:37"}

Pretty output:

$ ./call-api.py test/ping '{}' pretty
{
    "pong": "2020-10-26 23:06:42"
}

"""

import os
import sys
import json
import configparser
from shadowapi.call_api import Config, ShadowAPI


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read(os.environ['HOME'] + "/.shadowserver.api")

    if (len(sys.argv) < 3):
        exit("Usage: call-api.py method json [pretty|binary]")

    try:
        api_request = json.loads(sys.argv[2])
    except Exception as e:
        exit("JSON Exception: " + format(e))

    try:
        config.get('api', 'key')
    except configparser.NoSectionError:
        exit("Exception: " + os.environ['HOME'] + "/.shadowserver.api could "
             "not be found. Exiting.")

    try:
        conf = Config(config.get('api', 'key'), config.get('api', 'secret'), config.get('api', 'uri'))
        Shadow = ShadowAPI(conf)
        res = Shadow.api_call(sys.argv[1], api_request)
    except Exception as e:
        exit("API Exception: " + format(e))

    if (len(sys.argv) > 3):
       if (sys.argv[3] == "pretty"):
           try:
               print(json.dumps(json.loads(res), indent=4))
           except:
               print(res.decode('utf-8'))
       elif (sys.argv[3] == "binary"):
           os.write(1, res);
       else:
           exit("Unknown option " + sys.argv[3])
    else:
        print(res.decode('utf-8'))


