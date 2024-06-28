""" This module contains functions download files (usually json) of CVEs or CPE dictionary from NVD"""

import requests
import xml.etree.ElementTree as ET
from database.connection import connect_to_db, close_connection
from matching.db_match import cpe_match_from_db, match_cve_cpe
from database.asset import add_multiple_cpe
from database.cve import add_multiple_cve, update_cve_last_modified, update_multiple_cve
import mysql.connector
import time
from config import conf
import gzip
import json
import hashlib
from datetime import datetime
from debug.debug import debug_log, debug_new_line


""" Download cve JSON Feeds from NVD """
def download_file(url,path):
    debug_log('debug', 'Start download_file')
    print('\nDownloading file from: ',url)
    try:
        r = requests.get(url)
        # urllib.request.urlretrieve(url, path)
        print(r.status_code)

        with open(path, 'wb') as f:
            f.write(r.content)
        # Retrieve HTTP meta-data
        # print(r.headers['content-type'])
        # print(r.encoding)
    except Exception as error:
        msg = 'Failed to download file: ' + str(error)
        debug_log('error', msg)
        print('error in download file: check the url or the path!')
    finally:
        debug_log('debug', 'End download_file')

""" remove special beckslash-special_chars from the cpe id """
def remove_schars(cpe_id):
    cpe_id = cpe_id.replace('\:', '()')
    cpe_id = cpe_id.replace('\\', '')
    return cpe_id


""" Import NDV cpe dictionary"""
def import_cpe_dict():
    start_time = time.time()  # to calculate execution time
    debug_log('debug', 'Start import_cpe_dict')
    """ Download the cpe dictionary """
    print('Downloading the cpe dictionary ...')
    url = conf.get_source("cpe")
    path = conf.get_path("cpe")
    download_file(url, path)


    print('extracting cpes details from the xml file ...')
    with gzip.open(path, "rb") as f:
        tree = ET.parse(f)

    root = tree.getroot()
    ns = {'dict': 'http://cpe.mitre.org/dictionary/2.0',
          'cpe23': 'http://scap.nist.gov/schema/cpe-extension/2.3'}
    list = root.findall('dict:cpe-item', ns)
    i=1
    end_time = time.time()
    exec_time = end_time - start_time
    print('extracting cpe details from xml file execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        print(len(list), ' cpe contained in the dictionary')
        # print(list[0])
        print('Adding cpes to the list ...')
        asset_list = []
        list_start_time = time.time()
        for cpe in list:
            # print('cpe : ', cpe.attrib['name'])
            references = cpe.find('dict:references', ns)
            if (references):
                ref_list = references.findall('dict:reference', ns)
            cpe_id_schar = cpe.find('cpe23:cpe23-item', ns).attrib['name']
            cpe_id = remove_schars(cpe_id_schar)
            # print(i,':', cpe_id)
            cpe_elem = cpe_id.split(':')
            # print('cpe elemnts: ',cpe_elem)
            type = cpe_elem[2]
            producer = cpe_elem[3].replace('()',':')
            name = cpe_elem[4].replace('()',':')
            version = cpe_elem[-8].replace('()',':')
            # print('\tproducer:',producer)
            # print('\tname:',name)
            # print('\tversion:',version)
            # links=''
            # for ref in ref_list:
            #     links = links+ref.attrib['href']+'\t'
                # print('\t link: ',ref.attrib['href'])
            # print('references: ',links)

            # asset_record = {'cpe_id': cpe_id, 'type': type, 'producer': producer, 'name': name
            #             , 'version':version, 'links':links }
            # q.add_asset(asset_record,cursor)
            # connection.commit()
            # i = i + 1

            asset_element = [cpe_id_schar, type, producer, name, version]
            asset_list.append(asset_element)
        end_time = time.time()
        exec_time = end_time - list_start_time
        print('\nAdding cpes to the list execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
        print('\nAdding cpes entries to the DB ')
        add_multiple_cpe(cursor,asset_list)
        connection.commit()

    except Exception as error:
        msg = 'Failed to insert into cpe table: ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into cpe table {}".format(error))

    finally:
        end_time = time.time()
        exec_time = end_time - start_time
        print('import_cpe_dictionary execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")
        debug_log('debug', 'End import_cpe_dict')


""" import all CVEs entry from NVD to the database including the affected assets """
def import_all_CVEs(): # this process take too much time (around 6 hours)
    start_time = time.time()
    print('importing all CVEs to the database ... ')
    try:
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)

        for i in range(2003, 2021):
            name = "cve_"
            name = name + str(i)
            # print(i, name)

            path = conf.get_path(name)
            url = conf.get_source(name)
            download_file(url, path)  # download nvd cve json feed

            with gzip.open(path, "rb") as f:
                cve_dict = json.load(f)

            items_list = []
            cve_digest_list = []
            print('Getting the cve details from the json file: ')
            print('number of items in the cve json file: ', len(cve_dict['CVE_Items']))
            add_list = []
            update_list = []
            vuln_assets_list = []
            for i in cve_dict['CVE_Items']:
                cve_id = i['cve']['CVE_data_meta']['ID']
                # print('\ncve ID: ', cve_id)

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

                baseMetricV2 = 'baseMetricV2'
                if baseMetricV2 in i['impact']:
                    cvss2_base = i['impact']['baseMetricV2']['cvssV2']['baseScore']
                else:
                    cvss2_base = ""

                baseMetricV3 = 'baseMetricV3'
                if baseMetricV3 in i['impact']:
                    cvss3_base = i['impact']['baseMetricV3']['cvssV3']['baseScore']
                else:
                    cvss3_base = ""

                published_at = i['publishedDate']
                # print('published at: ', published_at)
                last_modified = i['lastModifiedDate']
                # print('last modified: ', last_modified)

                """ get the affected assets of the CVE"""
                vulnerable_assets = []
                cpe_match = 'cpe_match'
                # print('nodes: ',len(i['configurations']['nodes']))
                rangeStartType = ""
                rangeStartVersion = ""
                rangeEndVersion = ""
                rangeEndType = ""
                rangeID = False
                cpe_list = []
                if len(i['configurations']['nodes']) > 0:
                    if cpe_match in i['configurations']['nodes'][0]:
                        for cpe in i['configurations']['nodes'][0]['cpe_match']:
                            if "versionStartIncluding" in cpe:
                                rangeID = True
                                rangeStartType = "including"
                                rangeStartVersion = cpe["versionStartIncluding"]
                            elif "versionStartExcluding" in cpe:
                                rangeID = True
                                rangeStartType = "excluding"
                                rangeStartVersion = cpe["versionStartExcluding"]

                            if "versionEndtIncluding" in cpe:
                                rangeID = True
                                rangeEndType = "including"
                                rangeEndVersion = cpe["versionEndIncluding"]
                            elif "versionEndExcluding" in cpe:
                                rangeID = True
                                rangeEndType = "excluding"
                                rangeEndVersion = cpe["versionEndExcluding"]

                            cpe_dict = {'cpe_id': cpe['cpe23Uri'], 'range_id': rangeID,
                                        'rangeStartType': rangeStartType,
                                        'rangeStartVersion': rangeStartVersion,
                                        'rangeEndType': rangeEndType, 'rangeEndVersion': rangeEndVersion}
                            cpe_list.append(cpe_dict)
                final_cpe_list = cpe_match_from_db(cursor,cpe_list)
                vulnerable_assets.extend(final_cpe_list)
                # print('vulnerable assets:\n', vulnerable_assets)

                link = conf.get_source("nvd_cve") + cve_id
                digest = hashlib.md5(link.encode()).hexdigest()

                date = datetime.strptime(published_at, "%Y-%m-%dT%H:%MZ")

                cve_details = {"digest":digest,"cve_id": cve_id, "title": title, "description": description,
                               "links": links,"published_at": date, "last_modified": last_modified, "cvss2": cvss2_base,
                               "cvss3": cvss3_base,"mitigations": None, "workarounds": None, "vulnerable_assets": vulnerable_assets} # necessary if we want to update vulnerable_asset table
                # cve_digest_list.append(cve_details)  # save the digest with the collected cves in order to pass it to the update_modified_cve and match_cve_cpe functions.

                """ Add/Update CVEs in the DB"""
                select_Query = "select last_modified from cve where id = %s"
                select_record = (cve_details['cve_id'],)
                # cve_cursor = connection.cursor()
                cursor.execute(select_Query, select_record)
                record = cursor.fetchone()
                # print('record selected from cve: \n',record)

                if not (record):  # CVE does not exists in the DB (Add the CVE to the DB)
                    element = [cve_details['cve_id'], cve_details['title'], cve_details['description'],
                               cve_details['links'],
                               cve_details['published_at'], cve_details['cvss3'], cve_details['mitigations'],
                               cve_details['workarounds'], cve_details['last_modified'], cve_details['cvss2']]
                    # print('element: ',element)
                    add_list.append(element)
                    """ adding vulnerable assets of the cve to a list"""
                    if len(cve_details['vulnerable_assets']) > 0:  # there are assets affected by the vulnerabilities (cpe list)
                        vuln_asset = {"digest": cve_details["digest"],"cve_id": cve_details['cve_id'],
                                      "vulnerable_assets": cve_details["vulnerable_assets"]}
                        vuln_assets_list.append(vuln_asset)
                else:  # CVE already exists in the DB
                    # print('old last modified: ', old_lm)
                    old_lm = str(record["last_modified"])
                    # old_lm = '1970-01-01 00:00:00' # for testing
                    if (old_lm != cve_details['last_modified']):  # the CVE has been modified (Update the CVE in the DB)
                        element = [cve_details['description'], cve_details['links'], cve_details['cvss3'],
                                   cve_details['mitigations'], cve_details['workarounds'], cve_details['last_modified'],
                                   cve_details['cvss2'], cve_details['cve_id']]
                        update_list.append(element)
                        """ adding vulnerable assets of the cve to a list"""
                        if len(cve_details['vulnerable_assets']) > 0:  # there are assets affected by the vulnerabilities (cpe list)
                            vuln_asset = {"digest": cve_details["digest"],"cve_id": cve_details['cve_id'],"vulnerable_assets": cve_details["vulnerable_assets"]}
                            vuln_assets_list.append(vuln_asset)

            print('Number of CVE to add: ', len(add_list))
            add_multiple_cve(cursor, add_list)  # will be defined iin database
            connection.commit()

            update_cve_last_modified()  # will be defined iin database
            connection.commit()

            # print('Number of CVE to update: ',len(update_list))
            update_multiple_cve(update_list, cursor)  # will be defined iin database
            connection.commit()

            """ Adding cpe/cve entry to vulnerable_asset """
            last_date = match_cve_cpe(connection, vuln_assets_list)
            print(last_date)
            # break  # to test one file only

    except mysql.connector.Error as error:
        print("Failed in import_all_CVEs ({}): {}".format(name,error))

    finally:
        if connection.is_connected():
            cursor.close()
            close_connection(connection)
        """ Get execution time of the function"""
        end_time = time.time()
        exec_time = end_time - start_time
        print('import_all_CVEs execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))



""" Testing """
# debug_new_line()
# import_cpe_dict()