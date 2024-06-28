""" This module contain the functions that store permanently all collected vulnerabilities in the DB """

from database.connection import connect_to_db, close_connection
from datetime import datetime
import mysql.connector
import time
from matching.db_match import match_cve_cpe
from database.cve import add_multiple_cve, update_multiple_cve, update_cve_last_modified
from debug.debug import debug_log







""" store all collected vulnerabilities in the DB """
def store_vulnerabilities(all_cves):
    try:
        debug_log('debug','Start store_vulneabilities')
        start_time = time.time()
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        cve_add_list = []
        cve_update_list = []
        vuln_assets_add_list = []
        vuln_assets_archive_add_list = []
        current_year_cve = 'CVE-2021-'  # CVEs of the current year are treated separately from the others
        last_year = 'CVE-2020-'
        print('number of cves collected: ', len(all_cves))
        print('Getting the cve details ... ')
        for cve in all_cves:
            cve_id = cve['cve_id']
            # print('\ncve ID: ', cve_id)
            # check if the CVE has been modified since the last collect to proceed details's extraction
            last_modified_str = cve['last_modified']
            # print('last modified: ', last_modified)
            # last_modified = datetime.strptime(last_modified_str, "%Y-%m-%d %H:%M:%S")
            last_modified = last_modified_str

            select_Query = "select last_modified from cve where id = %s"
            select_record = (cve_id,)
            # cve_cursor = connection.cursor()
            cursor.execute(select_Query, select_record)
            record = cursor.fetchone()
            # print('record selected from cve: \n',record)

            if not (record):  # CVE does not exist in the DB (Add the CVE to the DB)
                """ Extracting details from the json file """
                title = cve_id + "(NIST)"

                description = cve['description']
                # print('Description: \n', description)
                links = cve['links']
                # print('links: ', links)

                cvss2_base = cve['cvss2']

                cvss3_base = cve['cvss3']

                published_at = cve['published_at']
                # print('published at: ', published_at)

                """ get the affected assets of the CVE"""
                vulnerable_assets = cve['vulnerable_assets']

                # digest = hashlib.md5(link.encode()).hexdigest()

                # pub_date = datetime.strptime(published_at, "%Y-%m-%dT%H:%MZ")

                mitigations = cve['mitigations']
                workarounds = cve['workarounds']
                """ Adding CVEs to the DB"""
                element = [cve_id, title, description, links, published_at, cvss3_base, mitigations, workarounds, last_modified_str, cvss2_base]
                # print('element: ',element)
                cve_add_list.append(element)

                """ Adding vulnerable assets to the DB"""
                if len(vulnerable_assets) > 0:  # there are assets affected by the vulnerabilities (cpe list)
                    vuln_asset = {"cve_id": cve_id, "vulnerable_assets": vulnerable_assets}
                    if (current_year_cve in cve_id) or (last_year in cve_id):  # add to vulnerable_assets table
                        vuln_assets_add_list.append(vuln_asset)
                    else:  # add to vulnerable_assets_archive table
                        vuln_assets_archive_add_list.append(vuln_asset)
            else:  # CVE already exists in the DB
                """ Updating CVEs in the DB"""
                old_lm = str(record["last_modified"])
                # old_lm = '1970-01-01 00:00:00' # for testing
                if (old_lm != str(last_modified)):  # the CVE has been modified (Update the CVE in the DB)
                    # print('cve_id:', cve_id, 'old last modified: ', type(old_lm), 'new date: ', type(last_modified))

                    """ Extracting details from the json file """
                    description = cve['description']
                    # print('Description: \n', description)
                    links = cve['links']
                    # print('links: ', links)
                    cvss2_base = cve['cvss2']
                    cvss3_base = cve['cvss3']

                    """ get the affected assets of the CVE"""
                    vulnerable_assets = cve['vulnerable_assets']

                    mitigations = cve['mitigations']
                    workarounds = cve['workarounds']
                    # digest = hashlib.md5(link.encode()).hexdigest()

                    element = [description, links, cvss3_base, mitigations, workarounds, last_modified, cvss2_base, cve_id]
                    # print('element: ',element)
                    cve_update_list.append(element)

                    """ Adding vulnerable assets to the DB"""
                    if len(vulnerable_assets) > 0:  # there are assets affected by the vulnerabilities (cpe list)
                        vuln_asset = {"digest": "", "cve_id": cve_id, "vulnerable_assets": vulnerable_assets}
                        if (current_year_cve in cve_id) or (last_year in cve_id):  # add to vulnerable_assets table
                            vuln_assets_add_list.append(vuln_asset)
                        else:  # add to vulnerable_assets_archive table
                            vuln_assets_archive_add_list.append(vuln_asset)

        """ Add/Update CVE in the DB"""
        if len(cve_add_list) > 0:
            add_multiple_cve(cursor, cve_add_list)
            connection.commit()
            # print('CVEs to add: ',len(cve_add_list))
            # for a in cve_add_list:
            #     print(a[0])

        update_cve_last_modified()
        connection.commit()

        if len(cve_update_list) > 0:
            # print('Number of CVE to update: ',len(cve_update_list))
            update_multiple_cve(cve_update_list, cursor)
            connection.commit()
            # print('CVEs to update: ', len(cve_update_list))
            # for a in cve_update_list:
            #     print(a[-1])

        """ Adding cpe/cve entry to vulnerable_asset """
        match_cve_cpe(connection, vuln_assets_add_list)
        # match_archive_cve_cpe(connection,vuln_assets_add_list,last_date)

    except Exception as error:
        msg = 'Failed in store_vulnerabilities(): ' + str(error)
        debug_log('error', msg)
        print("Failed in store_vulnerabilities {}".format(error))


    finally:
        if (connection.is_connected()):
            cursor.close()
            # cve_cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")
        end_time = time.time()
        exec_time = end_time - start_time
        # print('exec time: ',exec_time)
        print('store_vulnerabilities execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)),'\n')
        debug_log('debug', 'End store_vulneabilities')
