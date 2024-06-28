""" This module contain configurations (file paths, URLs, credentials) used by the other modules"""


import os
from mysql.connector import Error



sources = {
    "cpe": "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz",
    "cve_mod_meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta",
    "cve_recent_meta": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta",
    "nvd_cve": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=",
    "cve_2002": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz",
    "cve_2003": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz",
    "cve_2004": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz",
    "cve_2005": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz",
    "cve_2006": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz",
    "cve_2007": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz",
    "cve_2008": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz",
    "cve_2009": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz",
    "cve_2010": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz",
    "cve_2011": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz",
    "cve_2012": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz",
    "cve_2013": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz",
    "cve_2014": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz",
    "cve_2015": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz",
    "cve_2016": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz",
    "cve_2017": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz",
    "cve_2018": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz",
    "cve_2019": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz",
    "cve_2020": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz"
}

# Paths are to be update in the new environement
path = {
    "cpe": "database/cpe/cpe-dictionary_2.3.xml.gz",
    "cve_mod_meta": "Database/cve/last_modified_cve_feed.meta",
    "cve_recent_meta": "Database/cve/nvd_recent_cve.meta",
    "cve_mod": "Database/cve/last_modified_cve_feed.json.gz",
    "cve_recent": "Database/cve/nvd_recent_cve.json.gz",
    "cve_2002": "Database/cve/cve_2002.json.gz",
    "cve_2003": "Database/cve/cve_2003.json.gz",
    "cve_2004": "Database/cve/cve_2004.json.gz",
    "cve_2005": "Database/cve/cve_2005.json.gz",
    "cve_2006": "Database/cve/cve_2006.json.gz",
    "cve_2007": "Database/cve/cve_2007.json.gz",
    "cve_2008": "Database/cve/cve_2008.json.gz",
    "cve_2009": "Database/cve/cve_2009.json.gz",
    "cve_2010": "Database/cve/cve_2010.json.gz",
    "cve_2011": "Database/cve/cve_2011.json.gz",
    "cve_2012": "Database/cve/cve_2012.json.gz",
    "cve_2013": "Database/cve/cve_2013.json.gz",
    "cve_2014": "Database/cve/cve_2014.json.gz",
    "cve_2015": "Database/cve/cve_2015.json.gz",
    "cve_2016": "Database/cve/cve_2016.json.gz",
    "cve_2017": "Database/cve/cve_2017.json.gz",
    "cve_2018": "Database/cve/cve_2018.json.gz",
    "cve_2019": "Database/cve/cve_2019.json.gz",
    "cve_2020": "Database/cve/cve_2020.json.gz",
    "vulDB_feed": "collector/vulDB_API_result.json",
    "debug" : "debug/pgv_debug.log",
    "inventory" : "database/inventory/",
    "upload" : "../database/files/"
}

global vuldb
vuldb = {"account1":{'mail':'','login':'', 'mdp':'', 'api_key':'key_account1','credits':22,'last_colect':''},
         "account2":{'mail':'','login':'', 'mdp':'', 'api_key':'key_account2','credits':23,'last_colect':''},
         "account3":{'mail':'','login':'', 'mdp':'', 'api_key':'key_account3','credits':23,'last_colect':''}}





def get_source(source):
    try:
        if source in sources:
            return sources[source]
    except Error as e:
        print("Error in get_source: ",e)


def get_path(source):
    try:
        runPath = os.path.dirname(os.path.realpath(__file__))
        if source in path:
            file_path = os.path.join(runPath, "../" + path[source])
            return file_path
    except Error as e:
        print("Error in get_source: ",e)


""" Testing """
