""" This module contain the functions that collect new vulnerabilities from vulDB (source of vulnerabilities)"""


import json
from datetime import datetime
import time
# from config.conf import get_source
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import mysql.connector
from database.connection import connect_to_db, close_connection
from config import conf
from database.source import update_source
from debug.debug import debug_log
from config.conf import get_path
from database.vuldb_account import get_api_key, update_credit
import ssl
import certifi
import requests


""" get the last released vulnerabilities from vulDB """
def get_recent(url,last_timestamp,connection=None):
    debug_log('debug','Start get_recent()')
    jsn = None
    try:
        if not connection:
            connection = connect_to_db()
        api_key = get_api_key(connection)
        if not api_key:
            # api_key = 'd984ebb737e76a71eb9743e5efecff53' # api_ket of Billel account
            api_key = 'cb722e7212e608be2781c5789cbc5d2c' # api_ket of Zakaria_br account
        print('api_key: ',api_key)
        post_fields = {'apikey': api_key,
                       'details': '1',
                       'recent': '1', # changed from 10 to 1

                      # 'entry_timestamp_create_start': '1666626360', # to be defined before to lunch the test
                       # 'entry_timestamp_change_start': '1611564920', # for testing
                       'fields': 'entry_summary,software_cpe23,advisory_url'}  # request

        request = Request(url, urlencode(post_fields).encode())
        json_str = urlopen(request, context=ssl.create_default_context(cafile=certifi.where())).read().decode()
        # print('type json_str: ',type(json_str))
        jsn = json.loads(json_str)
        # print('type json: ',type(json))

        timestamp = jsn['response']['timestamp']
        dt_object = datetime.fromtimestamp(int(timestamp))
        str_date = dt_object.strftime("%Y-%m-%d %H:%M:%S")
        print("API feed date: ", str_date)
        dict = {str_date: json_str.replace('\\n', '\n')}
        credit_remaining = jsn['response']['remaining']
        update_credit(api_key,credit_remaining,connection)

        print(json_str)
        """ Save every request to the API in a file (vulDB_API_result.json)"""
        # debug_log('info','Saving vulDB collected vulnerabilities in a file ...') # Debugging
        # path = get_path('vulDB_feed')
        # with open(path, "a") as file:
        #     data = json.load(file)
        #     data.update(dict)
        #     file.seek(0)
        #     json.dump(data, file)
    except Exception as e:
        msg = 'Failed at get_recent(): ' + str(e)
        debug_log('error',msg)
    finally:
        debug_log('debug','End get_recent()')
        """ return a json file """
        return jsn



""" get the last updated vulnerabilities from vulDB """
def get_updates(url):
    debug_log('debug','Start get_updates()')
    post_fields = {'apikey': '287d88dc10bc979bbf86bdaa76065d16', 'updates': '5', 'details': '0',
                   'fields': 'entry_summary,software_cpe,advisory_url'}  # request

    request = Request(url, urlencode(post_fields).encode())
    json_str = urlopen(request).read().decode()
    # print('type json_str: ',type(json_str))
    jsn = json.loads(json_str)
    # print('type json: ',type(json))

    timestamp = jsn['response']['timestamp']
    dt_object = datetime.fromtimestamp(int(timestamp))
    str_date = dt_object.strftime("%Y-%m-%d %H:%M:%S")
    print("API feed date: ",str_date)
    dict = {str_date: json_str.replace('\\n', '\n')}

    # print(json_str)
    """ Save every request to the API in a file (vulDB_API_result.json)"""
    # with open("vulDB_API_result.json", "r+") as file:
    #     data = json.load(file)
    #     data.update(dict)
    #     file.seek(0)
    #     json.dump(data, file)

    debug_log('debug','End get_updates()')
    """ return a json file """
    return jsn

""" Collect last published vulneravilities from vulDB API  """
def get_vulDB_CVEs(id_source,url,type,last_timestamp): # return list of vulnerabilities details
    try:
        debug_log('debug', 'Start get_vulDB_CVEs()')
        start_time = time.time()
        connection = connect_to_db()
        debug_log('debug', 'connected to the database')
        # if type == 'updates':
        #     debug_log('debug', 'Collecting vulDB last updated vulnerabilities JSON feed')
        #     print('\nCollecting vulDB last updated vulnerabilities JSON feed: ', url)
        #     data = get_updates(url)
        # else:
        #     debug_log('debug', 'Collecting vulDB last published vulnerabilities JSON feed')
        #     print('\nCollecting vulDB last published vulnerabilities JSON feed: ', url)
        #     data = get_recent(url, last_timestamp,connection)  # api_key is set for test v0.1 only
        """ get vulDB feed from json file """  # Testing
        path = get_path('vulDB_feed')
        print("path", path)
        with open(path, "r") as file:  # collect the api feed stored in a file for testing
            debug_log('debug', 'opening file')
            data = json.load(file)

        """ getting current date """
        now = datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")
        """ getting the datetime of the API request """
        feed_timestamp = data["response"]["timestamp"]
        feed_date = datetime.fromtimestamp(int(feed_timestamp))
        print('feed date: ', feed_date)
        cve_digest_list = []

        cursor = connection.cursor()
        if "result" in data:
            debug_log('debug','Getting the cve details from vulDB API')
            print('Getting the cve details from vulDB API: ')
            for item in data["result"]:
                    cve_id = None
                    link = None
                    if "source" in item:
                        if "cve" in item["source"]:
                            cve_id = item['source']['cve']['id']
                            link = conf.get_source("nvd_cve") + cve_id
                    # print('\ncve ID: ', cve_id)

                    title = item['entry']['title']

                    if 'details' in item['entry']:
                        mitigations = item['entry']['details']['countermeasure']
                    else:
                        mitigations = None

                    description = item['entry']['summary']
                    # print('Description: \n', description)

                    if "url" in item['advisory']:
                        links = item['advisory']['url']
                    else:
                        links = ""
                    # print('links: ', links)

                    """ get the cvss score """
                    cvss2 = 'cvss2'
                    if cvss2 in item['vulnerability']:
                        cvss2_base_score = item['vulnerability']['cvss2']['vuldb']['basescore']
                        cvss2_temp_score = item['vulnerability']['cvss2']['vuldb']['tempscore']
                    else:
                        cvss2_base_score = ""
                        cvss2_temp_score = ""

                    cvss3 = 'cvss3'
                    if cvss3 in item['vulnerability']:
                        cvss3_base_score = item['vulnerability']['cvss3']['vuldb']['basescore']
                        cvss3_temp_score = item['vulnerability']['cvss3']['vuldb']['tempscore']
                    else:
                        cvss3_base_score = ""
                        cvss3_temp_score = ""

                    create_timestamp = item['entry']['timestamp']['create']
                    published_at = datetime.fromtimestamp(int(create_timestamp))
                    pub_date = published_at.strftime("%Y-%m-%d %H:%M:%S")
                    # published_at = dt_object.strftime("%Y-%m-%d %H:%M:%S")
                    # print('published at: ', published_at)

                    change_timestamp = item['entry']['timestamp']['change']
                    dt_object = datetime.fromtimestamp(int(change_timestamp))
                    last_modified = dt_object.strftime("%Y-%m-%d %H:%M:%S")
                    # print('last modified: ', last_modified)

                    vulnerable_assets = []
                    cpe23 = 'cpe23'
                    if cpe23 in item['software']:
                        for cpe in item['software']['cpe23']:
                            vulnerable_assets.append(cpe)
                    # print('vulnerable assets:\n', vulnerable_assets)

                    if not link: # if there are no cve_id
                        link = links # link is the advisory url (vulDB)
                    # digest = hashlib.md5(link.encode()).hexdigest() # digest is not nedded if we don't add in item table

                    cve_details = {"cve_id":cve_id,"title":title,"description":description,"links":links,"published_at":pub_date,"last_modified":last_modified,
                                   "cvss2":cvss2_base_score,"cvss3":cvss3_base_score,"temp_cvss2":cvss2_temp_score,"temp_cvss3":cvss3_temp_score,
                                   "mitigations":mitigations,"workarounds":None,"vulnerable_assets":vulnerable_assets}
                    cve_digest_list.append(cve_details) # save the digest with the collected cves in order to pass it to the update_modified_cve and match_cve_cpe functions.
                    # break

        """ Update source date (last update)"""
        update_source(id_source, feed_date, cursor)
        connection.commit()


    except mysql.connector.Error as error:
        msg = 'Failed in get_vulDB_CVEs(): ' + str(error)
        debug_log('error',msg)
        print("Failed in get_vulDB_CVEs {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            # cve_cursor.close()
            close_connection(connection)
            # debug_log('debug','Mysql connection is close')
            # print("MySQL connection is closed")
        end_time = time.time()
        exec_time = end_time - start_time
        # print('exec time: ',exec_time)
        print('get_vulDB_CVEs execution time: ',time.strftime("%H:%M:%S", time.gmtime(exec_time)),'\n')
        debug_log('debug','End Get_vulDB_CVEs() ')
        return cve_digest_list




def get_vuls(url, data):
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
        json_content = response.json()
        return json_content
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        return None