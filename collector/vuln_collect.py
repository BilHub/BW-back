""" This module contain the main function (collect_vulnerabilities) of the hole process.
 it call the functions of data gathering, matching and then sendinng alerts to the client"""

from alert.sender import send_alerts
from database.connection import connect_to_db, close_connection
from datetime import datetime
import mysql.connector
from collector.vulDB import get_vulDB_CVEs, get_vuls
from matching.client_match import match_cve_client_assets
from matching.client_match import match_client_vuln_assets
from collector.nvd import get_nvd_last_CVEs
from database.vuln_asset import get_temp_vuln_assets_records
from debug.debug import debug_log
from database.vuldb_account import get_api_key
import json
import subprocess
from cryptography.fernet import Fernet
import base64
from dateutil.relativedelta import *
from datetime import datetime
import pytz
import jwt

""" collect CVEs from all sources (NDV and vulDB) """
def collect_vulnerabilities(): # collect separetly from NVD and vulDB and match with client assets
    debug_log('info','colleccting vulnerabilities ....')
    debug_log('debug','Sart collect_vulnerabilities()')
    all_cves = [] # list of all cve collected from both NVD & vulDB
    try:
        debug_log('debug','Collecting vulnerabilities')
        print('collecting vulnerabilities ...')
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True)
        # debug_log('debug','connected to the database')

        """collecting vulnerabilities from vulDB"""
        # select_query = """ select id, full_url, last_update, change_entry from source where sourcename like 'vulDB recent%' """
        # cursor.execute(select_query)
        # record = cursor.fetchone()
        #
        # id_source = record['id']
        # url = record['full_url']
        # print('url: ', url)
        # last_update = record['last_update']
        # #last_timestamp = int((datetime.timestamp(last_update)))
        # last_timestamp = record['change_entry']
        # print('last_update time: ',last_timestamp)
        type = 'recent'
        # api_key = get_api_key() # ths function is used only for the test v0.1
        # select_query = """ select id_server, jwt, email, license from license where idLicense like '3' """
        # cursor.execute(select_query)
        # record = cursor.fetchone()
        #id_source = record['id']
        select_query = """ select idLicense, id_server, secret_key, email, last_call, license, secret_key, secret_key_license from license where idLicense like '1' """
        cursor.execute(select_query)
        record = cursor.fetchone()
        # print('record', record)
        #id_source = record['id']
        url_aws = 'https://license.loadbalancerbw.click/get-vulnerabilities'
        cipher_suite = Fernet(record['secret_key_license'])
        encrypted_bytes = cipher_suite.encrypt(record['license'].encode('utf-8'))
        encrypted_string = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        timezone = pytz.timezone('UTC')
        start_date = datetime.now(timezone)
        expire_date = start_date + relativedelta(minutes=70)
        payload = {
            "sub": encrypted_string,
            "iat": start_date,
            "exp": expire_date
        }
        # print('payload', payload)
        jwt_token = jwt.encode(payload, record['secret_key'], algorithm='HS256')
        now = datetime.now()
        update_query = """UPDATE license SET jwt = %(jwt)s, last_call = %(last_call)s WHERE idLicense = %(id)s"""
        query_params = {
            'jwt': jwt_token,
            'id': record['idLicense'],
            'last_call': now
        }
        cursor.execute(update_query, query_params)
        url_aws = 'https://license.loadbalancerbw.click/get-vulnerabilities'
        output = subprocess.check_output(['dmidecode', '-s', 'system-uuid'])
        unique_id = output.decode('utf-8').strip()
        # print('machine_id', unique_id)
        post_data = {
            'id': record['id_server'],
            'jwt': jwt_token,
            'email': record['email'],
            'machine_id': unique_id, 
            'last_call': record['last_call']
        }
        # print('post_data', post_data)

        res = get_vuls(url_aws, post_data)
        # print('res', res)
        cves_list = res['content']
      #  cves_list = json.loads(res['content'])
        # print("all cves", cves_list)

        # cves_list = get_vulDB_CVEs(id_source,url,type,last_timestamp)
        # msg = f""" {len(cves_list)} collected from vulDB"""
        # debug_log('info', msg)
        # all_cves.extend(cves_list)
        # print("all cves", all_cves)
        """add new CVEs to cve_temp"""
        with open("/var/www/backend/collector/vul_res_test.json", "w") as final:
            json.dump(cves_list, final)
        with open("/var/www/backend/collector/vul_res_test.json", "r") as read_file:
            data = json.load(read_file)




        match_cve_client_assets(connection,data,"vulDB")

        """collecting vulnerabilities from NVD"""
        # select_query = """ select id, full_url, last_update from source where sourcename like 'NVD%API%' """
        # cursor.execute(select_query)
        # record = cursor.fetchone()
        #
        # id_source = record['id']
        # url = record['full_url']
        # # print('url: ', url, 'last update: ', record["last_update"])
        # last_update = record['last_update']
        # cves_list = get_nvd_last_CVEs(id_source, url,last_update)
        # msg = f""" {len(cves_list)} collected from NVD"""
        # debug_log('info', msg)
        # all_cves.extend(cves_list)
        # # add new CVEs to cve_temp and match vulnerable CPEs with client CPEs
        # match_cve_client_assets(connection, cves_list, "NVD")

        last_vuln_assets = get_temp_vuln_assets_records(connection)
        if(len(last_vuln_assets)) > 0:
            client_asset_list = match_client_vuln_assets(connection,last_vuln_assets)
            print('client asset list', client_asset_list)
            send_alerts(connection,client_asset_list) # we have to fix mail problem first
        debug_log('debug', 'Collect finished without errors')
    except mysql.connector.Error as error:
        msg = 'Failed in collect_vulnerabilities(): '+ str(error)
        debug_log('error',msg)
        print("Failed in collect_vulnerabilities(): {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            debug_log('debug','Mysql connection is close')
            # print("MySQL connection is closed")
            return all_cves
