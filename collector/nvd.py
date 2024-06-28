""" This module contain the functions that collect new vulnerabilities from NVD """
import time
import requests
import json
from datetime import datetime
from mysql.connector import Error
from database.connection import connect_to_db, close_connection
from database.source import update_source
from debug.debug import debug_log





""" getting information from NVD API """
def nvd_API(url,last_date):
    start_time = time.time()
    result = None
    try:
        str_date = last_date.strftime("%Y-%m-%dT%H:%M:%S:000 Z")
        # str_date = '2021-06-07T08:37:000 Z' # for test
        # str_date = '2021-06-10T10:03:000 Z' # for test
        args = {
            'startIndex': '0',
            'resultsPerPage': '1000',
            'modStartDate': str_date,
            'addOns' : 'dictionaryCpes'
        }
        startindex = f"""startIndex={args['startIndex']}"""
        resultsPerPage = f"""resultsPerPage={args['resultsPerPage']}"""
        modStartDate = f"""modStartDate={args['modStartDate']}"""
        addOns = f"""addOns={args['addOns']}"""

        params = f"""?{startindex}&{resultsPerPage}&{modStartDate}&{addOns}"""
        # params = f"""?{startindex}&{resultsPerPage}&{modStartDate}""" # testing without addOns argument

        uri = url + params
        print('uri: ', uri)
        response = requests.get(uri)
        # print('type response: ', type(response))
        # print('response: ', response.status_code)
        if response.status_code == 200:
            json_data = json.loads(response.text)
            # print('json_date: \n',type(json_data))
            result = json_data['result']

    except Exception as e:
        print('Failed in nvd_API()!')
        msg = 'Failed in nvd_API(): ' + str(e)
        debug_log('error',msg)

    finally:
        end_time = time.time()
        exec_time = end_time - start_time
        # print('exec time: ',exec_time)
        print('\nnvd_API execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)), '\n')
        return result


""" Collect NVD last modified vulnerabilities via the API """
def get_nvd_last_CVEs(id_source,url,last_update): # nvd last modified cve via API
    start_time = time.time()
    print('\nCollecting NVD last modified CVE from API ... ',)

    print('last_update date: ',last_update)
    cve_digest_list = []

    """ Insert item into database"""
    try:
    # if 1==1: # show errors for debugging
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)
        feed = nvd_API(url,last_update)
        if feed:
            cve_list = feed['CVE_Items']
            print('number of items collected from NVD API: ',len(cve_list))
            print('Getting the cve details ... ')
            for i in cve_list:
                cve_id = i['cve']['CVE_data_meta']['ID']
                # print('\ncve ID: ', cve_id)
                last_modified_str = i['lastModifiedDate']
                # print('last modified: ', last_modified)
                last_modified = datetime.strptime(last_modified_str, "%Y-%m-%dT%H:%MZ")

                """check if the CVE has been modified since the last collect to proceed details's extraction""" # useless for the current configuration
                # select_Query = "select last_modified from cve_temp where id = %s"
                # select_record = (cve_id,)
                # # cve_cursor = connection.cursor()
                # cursor.execute(select_Query, select_record)
                # record = cursor.fetchone()
                # # print('record selected from cve: \n',record)

                """ get the affected assets of the CVE if they exist"""
                vulnerable_assets = []
                if "configurations" in i:
                    cpe_match = 'cpe_match'

                    for n in i['configurations']['nodes']:
                        if 'children' in n:  # there are chldrens element in the node
                            for child in n['children']:
                                for cpe in child['cpe_match']:
                                    if cpe['vulnerable'] == True:
                                        if "cpe_name" in cpe:  # the cpe names exist in the cpe dictionnary
                                            for name in cpe['cpe_name']:
                                                vulnerable_assets.append(name['cpe23Uri'])
                                        else:
                                            vulnerable_assets.append(cpe['cpe23Uri'])
                        else:
                            for cpe in n['cpe_match']:
                                if cpe['vulnerable'] == True:
                                    if "cpe_name" in cpe:  # the cpe names exist in the cpe dictionnary
                                        for name in cpe['cpe_name']:
                                            vulnerable_assets.append(name['cpe23Uri'])
                                    else:
                                        vulnerable_assets.append(cpe['cpe23Uri'])

                if len(vulnerable_assets) > 0:  # CVE entry contains vulnerable cpes
                    """ Extracting details from the json file """
                    title = cve_id + "(NIST)"

                    description = i['cve']['description']['description_data'][0]['value']
                    # print('Description: \n', description)

                    links_list = []
                    url_string = 'url'
                    if len(i['cve']['references']['reference_data']) > 0:
                        for reference in i['cve']['references']['reference_data']:
                            if url_string in reference:
                                links_list.append(reference['url'])
                        link_str = ', '
                        links = link_str.join(links_list)
                    else:
                        links = ""
                    # print('links: ', links)

                    if 'impact' in i:
                        # CVSS V3
                        if 'baseMetricV3' in i['impact']:
                            cvssv3_base_score = i['impact']['baseMetricV3']['cvssV3']['baseScore']
                            cvssv3_vector_string = i['impact']['baseMetricV3']['cvssV3']['vectorString']

                        else:
                            cvssv3_base_score = None
                            cvssv3_vector_string = None

                        #  CVSS V2
                        if 'baseMetricV2' in i['impact']:
                            cvssv2_base_score = i['impact']['baseMetricV2']['cvssV2']['baseScore']
                            cvssv2_vector_string = i['impact']['baseMetricV2']['cvssV2']['vectorString']
                        else:
                            cvssv2_base_score = None
                            cvssv2_vector_string = None
                    else:
                        cvssv3_base_score = None
                        cvssv3_vector_string = None
                        cvssv2_base_score = None
                        cvssv2_vector_string = None

                    published_at = i['publishedDate']
                    # print('published at: ', published_at)


                    # date = datetime.strptime(published_at, "%Y-%m-%dT%H:%MZ")

                    cve_details = {"cve_id": cve_id, "title": title, "description": description, "links": links,
                                   "published_at": published_at, "last_modified": last_modified,
                                   "cvss2": cvssv2_base_score, "cvss3": cvssv3_base_score,
                                   "mitigations": None, "workarounds": None,
                                   "vulnerable_assets": vulnerable_assets}
                    cve_digest_list.append(cve_details)


            """ Update source date (last update)"""
            str_feed_date = feed['CVE_data_timestamp']
            feed_date = datetime.strptime(str_feed_date, "%Y-%m-%dT%H:%MZ")
            print('feed date: ',feed_date)
            update_source(id_source, feed_date, cursor) # will be defined in database directory
            connection.commit()
    except Error as error:
        print("Failed in get_nvd_last_CVEs {}".format(error))
        msg = 'Failed in get_nvd_last_CVEs(): ' + str(error)
        debug_log('error', msg)

    finally:
        if (connection.is_connected()):
            cursor.close()
            # cve_cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")
        end_time = time.time()
        exec_time = end_time - start_time
        # print('exec time: ',exec_time)
        print('get_last_nvd-cves execution time: ',time.strftime("%H:%M:%S", time.gmtime(exec_time)),'\n')
        return cve_digest_list

