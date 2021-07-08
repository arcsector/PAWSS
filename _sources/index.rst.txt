.. Shadowserver API documentation master file, created by
   sphinx-quickstart on Tue Jul  6 22:39:15 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Shadowserver API's documentation!
============================================

This is the API wrapper for Shadowserver's v2 API. For more information, visit the official `Shadowserver API Documentation <https://www.shadowserver.org/what-we-do/network-reporting/api-documentation/>`_.

Installation
^^^^^^^^^^^^

To install the module, run:

.. code:: bash

   git clone https://github.com/arcsector/PAWSS
   cd PAWSS
   python setup.py install

Usage
^^^^^

To import and use the module, run:

.. code:: python

   from shadowapi import Config, ShadowAPI
   from shadowapi import ReportTypes, QueryFilters, SSLQuery

   config = {
    "key": "AAA-AAA",
    "secret": "BBB-CCC",
    "uri": "https://transform.shadowserver.org/api2/"
   }

   c = Config(**config)
   S = ShadowAPI(c)


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   download
   shadowapi


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
