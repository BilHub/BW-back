""" This module contains functions that match vulnerable cpes with the cpes used by cleints, than craete tickets for clients users"""


from database.connection import connect_to_db, close_connection
from database.cve import add_multiple_cve, add_multiple_cve_temp, calculate_final_score
from database.ticket import insert_tickets_from_list
from database.vuln_asset import add_multiple_temp_vulnerable_asset, add_multiple_client_vulnerable_asset, clear_temp_vuln_assets
import mysql.connector
from datetime import datetime
import time
from debug.debug import debug_log
from natsort import natsorted
from operator import itemgetter
from collector.download import remove_schars
from packaging import version as vrs
from jira import JIRA
from requests_toolbelt import user_agent

""" Getting the list of all cpes matching (cpe_id) in a dictionary sorted with version number from the database """
# def get_cpe_list(cpes_list): # this function match with collect vulDB API json feed ### Obsolètte
#     # print('get_cpe_list function:') # debugging
#     try:
#         # print('dict: ',dict)
#         connection = connect_to_db()
#         cursor = connection.cursor(dictionary=True,buffered=True)
#
#         selected_cpes = []
#         add_list = [] # list of the cpes to be added in the DB (cpe table)
#         # print('getting cpe id, version from the DB') # debugging
#         queries = [] # list of arguments off all queries passed
#         for cpe in cpes_list:
#             # print('cpe in vulnerable asset list: ',cpe) # debugging
#             cpe_elem = cpe.replace("*","%")
#             # print('cpe replaced: ', cpe_elem)  # debugging
#             str_list = cpe_elem.split(':')
#             # print('cpe str_list: ',str_list) # debugging
#             cpe_arg = ':'.join(str_list[0:6])+'%'
#             # print('cpe_arg: ', cpe_arg)  # debugging
#             select_Query = "select id_cpe from cpe where id_cpe like %s"
#             arg = (cpe_arg,)
#             cursor.execute(select_Query, arg)
#             records = cursor.fetchall()
#             # print('number of records selected for {} is: {}'.format(cpe_arg,len(records)))
#             # print('records: ',records)
#             # for c in records:
#             #     print(c)k
#             if len(records) == 0:  # cpe id does not exist in the DB (cpe table), looking for cpe id with all versions (exclude version from matching)
#                 # print('Getting the id_cpe of all versions')
#                 cpe_elem = cpe_arg.split(':')
#                 # print('cpe_elem: ', cpe_elem)
#                 # cpe_elem[-8] = "%"
#                 new_cpe_arg = ':'.join(cpe_elem[0:5]) + '%'
#                 if new_cpe_arg not in queries:  # execute query if the cpe_arg hasn't been requested before (to not execute the same request many times)
#                     # print('cpe_all_version: ', new_cpe_arg)
#                     arg = (new_cpe_arg,)
#                     cursor.execute(select_Query, arg)
#                     new_records = cursor.fetchall()
#                     # print('number of records selected for {} is: {}'.format(new_cpe_arg, len(new_records)))  # debugging
#                     if len(new_records) != 0:  # there are entries for other versions of the cpe id in the DB
#                         # print('Adding cpe id of all versions to the list')
#                         sorted_cpes = natsorted(new_records, key=itemgetter(*['version']))
#                         # print('sorted cpes:\n',len(sorted_cpes))
#                         for r in new_records:
#                             if r['id_cpe'] not in selected_cpes:
#                                 selected_cpes.append(r['id_cpe'])
#                     else:
#                         # print('there are no entries of the cpe id in the DB')
#                         # cpe_id = remove_schars(cpe)
#                         # print(i,':', cpe_id)
#                         # cpe_elem = cpe_id.split(':')
#                         # version = cpe_elem[-8].replace('()', ':')
#                         # cpe_dict = {'id_cpe':cpe,'version':version} # add the id_cpe to the list of cpes
#                         selected_cpes.append(cpe)
#                     queries.append(new_cpe_arg)
#                 else:
#                     selected_cpes.append(cpe)
#
#                 # Add the cpe id to the DB (adding th cpe to the list first)
#                 cpe_id = remove_schars(cpe)
#                 # print(i,':', cpe_id)
#                 cpe_elem = cpe_id.split(':')
#                 # print('cpe elemnts: ',cpe_elem)
#                 type = cpe_elem[2]
#                 producer = cpe_elem[3].replace('()', ':')
#                 name = cpe_elem[4].replace('()', ':')
#                 version = cpe_elem[-8].replace('()', ':')
#                 # print('\tproducer:',producer)
#                 # print('\tname:',name)
#                 # print('\tversion:',version)
#                 links = ''
#                 # print('references: ',links)
#
#                 asset_element = [cpe, type, producer, name, version, links]
#                 add_list.append(asset_element)
#
#             else: # there are a cpe entries in the DB
#                 # print('there are a cpe entries in the DB') # debugging
#                 """ Sort the cpe list according to the version"""
#                 sorted_cpes = natsorted(records, key=itemgetter(*['version']))
#                 print('sorted cpes:\n',len(sorted_cpes))
#                 for r in records:
#                     if r['id_cpe'] not in selected_cpes:
#                         selected_cpes.append(r['id_cpe'])
#                 for dict in sorted_cpes:
#                     selected_cpes.append(dict['id_cpe'])
#
#         # if len(add_list)>0:
#         #     # print('vulDB assets to add:')
#         #     # for i in add_list:
#         #     #     print(i)
#         #     cursor = connection.cursor(dictionary=True, buffered=True)
#         #     add_multiple_asset(cursor,add_list)
#         #     connection.commit()
#         # print('selected_cpes:\n', selected_cpes)
#         # print('Sorted cpes: ')
#         # i=0
#         # for s in sorted_cpes:
#         #     print(i,s)
#         #     i = i+ 1
#         # print('selected cpes: ')
#         # for s in selected_cpes:
#         #     print(s)
#     except mysql.connector.Error as error:
#         print("Failed to get values from cpe table: {}".format(error))
#
#     finally:
#         if (connection.is_connected()):
#             cursor.close()
#             close_connection()
#             # print("MySQL connection is closed")
#             return selected_cpes



""" Getting the list of all cpes (cpe_id) from client_cpe  """
def get_cpe_from_client_cpe(cpes_list,connection=None): # this function match with collect_vulDB_feed  (match_cve_client_cpe)
    # print('get_cpe_list function:') # debugging
    try:
        # print('dict: ',dict)
        if not connection:
            connection = connect_to_db()
        # debug_log('debug','Connected to mysql database')
        cursor = connection.cursor(dictionary=True,buffered=True)

        selected_cpes = []
        add_list = [] # list of the cpes to be added in the DB (cpe table)
        # print('getting cpe id, version from the DB') # debugging
        queries = [] # list of arguments off all queries passed
        for cpe in cpes_list:
            # print('cpe in vulnerable cpe list: ',cpe) # debugging
            cpe_elem = cpe.replace("*","%")
            # print('cpe replaced: ', cpe_elem)  # debugging
            str_list = cpe_elem.split(':')
            # print('cpe str_list: ',str_list) # debugging
            cpe_arg = ':'.join(str_list[0:6])+'%'
            # print('cpe_arg: ', cpe_arg)  # debugging
            select_Query = "select id_cpe, version from client_cpe where id_cpe like %s"
            arg = (cpe_arg,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('number of records selected for {} is: {}'.format(cpe_arg,len(records)))
            # print('records: ',records)
            # for c in records:
            #     print(c)k
            if len(records) == 0:  # cpe id does not exist in the DB (client_cpe table), looking for cpe id with all versions
                # print('Getting the id_cpe of all versions')
                cpe_elem = cpe_arg.split(':')

                new_cpe_arg = ':'.join(cpe_elem[0:5]) + '%'
                if new_cpe_arg not in queries:  # execute query if the cpe_arg hasn't been requested before (to not execute the same request many times)
                    # print('cpe_all_version: ', new_cpe_arg)
                    arg = (new_cpe_arg,)
                    cursor.execute(select_Query, arg)
                    new_records = cursor.fetchall()
                    # print('number of records selected for {} is: {}'.format(new_cpe_arg, len(new_records)))  # debugging
                    if len(new_records) != 0:  # there are entries for other versions of the cpe id in the DB
                        """ Cheking if the cpe id contain version nember"""
                        cpe_version = cpe_elem[5]
                        if cpe_version == '*':  # Adding cpe id of all versions to the list
                            # print('Adding cpe id of all versions to the list')
                            # sorted_cpes = natsorted(new_records, key=itemgetter(*['version']))
                            # print('sorted cpes:\n',len(sorted_cpes))
                            for r in new_records:
                                if r['id_cpe'] not in selected_cpes:
                                    selected_cpes.append(r['id_cpe'])
                        else: # cpe id doesn't has a version number
                            """ Adding only previous versions to the list """
                            for r in new_records:
                                if (vrs.parse(r['version']) < vrs.parse(cpe_version)) and r['id_cpe'] not in selected_cpes:
                                    selected_cpes.append(r['id_cpe'])
                    queries.append(new_cpe_arg)

            else: # there are a cpe entries in the DB
                # print('there are a cpe entries in the DB') # debugging
                # """ Sort the cpe list according to the version"""
                # sorted_cpes = natsorted(records, key=itemgetter(*['version']))
                # print('sorted cpes:\n',len(sorted_cpes))
                for r in records:
                    if r['id_cpe'] not in selected_cpes:
                        selected_cpes.append(r['id_cpe'])

        # print('selected_cpes:\n', selected_cpes)
        # print('Sorted cpes: ')
        # i=0
        # for s in sorted_cpes:
        #     print(i,s)
        #     i = i+ 1
        # print('selected cpes: ')
        # for s in selected_cpes:
        #     print(s)
    except mysql.connector.Error as error:
        msg = 'Failed in get_cpe_from_client_cpe(): ' + str(error)
        debug_log('error',msg)
        print("Failed to get values from cpe table: {}".format(error))

    finally:
        # if (connection.is_connected()): # connection should be closed in the parent function (collect_vulnerabilities())
        #     cursor.close()
        #     close_connection(connection)
        #     debug_log('debug','Mysql connectio is closed')
            # print("MySQL connection is closed")
            return selected_cpes


""" Getting the list of NVD cpe's (vulnerable assets of the CVEs) from client_cpe if they exists  """
def get_nvd_cpes_from_client_cpe(cpes_list): # this function match with collect_vulDB_feed  (match_cve_client_cpe)
    # print('get_cpe_list function:') # debugging
    # selected_cpes = []
    debug_log('debug','Start get_nvd_cpes_from_client_cpe')
    try:
        # print('dict: ',dict)
        connection = connect_to_db()
        debug_log('debug','connected to mysql database')
        cursor = connection.cursor(dictionary=True,buffered=True)

        selected_cpes = []
        # print('getting cpe id, version from the DB') # debugging
        queries = [] # list of arguments off all queries passed
        for cpe in cpes_list:
            # print('cpe in vulnerable cpe list: ',cpe) # debugging
            cpe_elem = cpe.replace("*","%")
            # print('cpe replaced: ', cpe_elem)  # debugging
            str_list = cpe_elem.split(':')
            # print('cpe str_list: ',str_list) # debugging
            cpe_arg = ':'.join(str_list[0:6])+'%'
            # print('cpe_arg: ', cpe_arg)  # debugging
            select_Query = "select id_cpe from client_cpe where id_cpe like %s"
            arg = (cpe_arg,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('number of records selected for {} is: {}'.format(cpe_arg,len(records)))
            # print('records: ',records)
            # for c in records:
            #     print(c)k
            if len(records) > 0:
                for r in records:
                    if r['id_cpe'] not in selected_cpes:
                        selected_cpes.append(r['id_cpe'])

    except mysql.connector.Error as error:
        msg = 'Failed in get_nvd_cpes_from_client_cpe(): ' + str(error)
        debug_log('error',msg)
        print("Failed to get values from cpe table: {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            debug_log('debug','Mysql connection is closed')
            # print("MySQL connection is closed")
            debug_log('debug','End get_nvd_cpes_from_client_cpe')
            return selected_cpes


""" adding vulDB/NVD CVEs to cve_temp and match vuln cpes with client cpes """
def  match_cve_client_assets(connection,cve_details_list,source):
    debug_log('debug','Start match_cve_client_assets()')
    start_time = time.time() # to calculate execution time
    created_at = None
    added_cve = 0
    try:
    # if 1==1: # debugging
        # cve_details = {"cve_id": cve_id, "title": title, "description": description, "links": links,
        #                "published_at": published_at, "last_modified": last_modified, "cvss2": cvss2_base_score,
        #                "cvss3": cvss3_base_score,
        #                "mitigations": None, "workarounds": None, "vulnerable_assets": vulnerable_assets}
        cursor = connection.cursor(dictionary=True, buffered=True)
        print('Number of items collected: ', len(cve_details_list))

        update_list = []
        add_list = []
        vuln_assets_list = []  # list containing cves that has been added or updated (cve_id, digest, vulnerable_assets)
        debug_log('debug','Getting the CVEs details in match_cve_client_assets')
        print('\nGetting the CVEs details in match_cve_client_assets ...')
        for cve_details in cve_details_list:
            if cve_details['cve_id']:
                # cve_temp record : (id, title, description, links, published_at, cvss3, mitigations, workarounds, last_modified, cvss2)
                    element = [cve_details['cve_id'], cve_details['title'], cve_details['description'],
                               cve_details['links'],
                               cve_details['published_at'], cve_details['temp_cvss3'], cve_details['mitigations'],
                               cve_details['workarounds'], cve_details['last_modified'], cve_details['temp_cvss2']]
                    # print('element: ',element)
                    add_list.append(element)
                    if len(cve_details['vulnerable_assets']) > 0:  # there are assets (cpes) affected by the vulnerabilities (cpe list)
                        vuln_asset = {"cve_id": cve_details['cve_id'], "vulnerable_assets": cve_details["vulnerable_assets"]}
                        vuln_assets_list.append(vuln_asset)
                # else:  # CVE already exists in the DB
                #     old_lm = str(record["last_modified"])
                #     # # old_lm = '1970-01-01 00:00:00' # for testing
                #     if (old_lm != str(
                #             cve_details['last_modified'])):  # the CVE has been modified (Update the CVE in the DB)
                #         # print('cve_id:', cve_details['cve_id'], 'old last modified: ', type(old_lm), 'new date: ',
                #         #       type(cve_details['last_modified']))
                #         element = [cve_details['description'], cve_details['links'], cve_details['cvss3'],
                #                    cve_details['mitigations'], cve_details['workarounds'], cve_details['last_modified'],
                #                    cve_details['cvss2'], cve_details['cve_id']]
                #         update_list.append(element)
                #         if len(cve_details[
                #                    'vulnerable_assets']) > 0:  # there are assets affected by the vulnerabilities (cpe list)
                #             vuln_asset = {"digest": cve_details["digest"], "cve_id": cve_details['cve_id'],
                #                           "vulnerable_assets": cve_details["vulnerable_assets"]}
                #             vuln_assets_list.append(vuln_asset)
        msg = f"""{len(vuln_assets_list)} of the collected CVEs that contain vulnerable CPEs """
        debug_log('info', msg)
        # print('Number of CVE to add: ',len(add_list))
        # for a in add_list:
        #     print(a[0])
        if len(add_list) >= 0:
            added_cve = add_multiple_cve_temp(cursor, add_list)
            connection.commit()

            # print('number of added cve: ',added_cve)
            # print('number of vuln assets list: ',len(vuln_assets_list))

            if added_cve > 0 and len(vuln_assets_list) > 0: # the are new CVEs and it contain vulnerable cpes
            # if 1 == 1: #  for testing
                # print('Number of CVE to match: ', len(vuln_assets_list))

                now = datetime.now()
                created_at = now.strftime("%Y-%m-%d %H:%M:%S")
                cursor = connection.cursor()
                add_list = []
                debug_log('debug','Getting affected assets in the CVEs from the Database')
                print('Getting affected assets in the CVEs from the Database ...')
                for vuln_asset_details in vuln_assets_list:
                    cve_id = vuln_asset_details['cve_id']
                    # print('\ncve_id: ', cve_id)
                    # print('\ncve_id: ', vuln_asset_details['cve_id']) # debugging
                    # print('Number of cpes affected to the CVE: ', len(vuln_asset_details['vulnerable_assets'])) # debugging
                    if source =='NVD':
                        cpes_list = get_nvd_cpes_from_client_cpe(vuln_asset_details['vulnerable_assets'])
                    else:
                        cpes_list = get_cpe_from_client_cpe(vuln_asset_details['vulnerable_assets'],connection)
                    # print('Number of cpes collected from the database: ', len(cpes_list)) # debugging

                    # print('cpe list lenght: ',len(cpes_list))
                    # Getting  last_modified of the cve from the DB
                    # connection = q.connect_to_db()
                    # print('record selected from item: ',record)

                    # if (record): # to avoid errors (be sure that the item id is selected)
                    for cpe in cpes_list:
                        # print('Adding vulnerable_asset...')
                        # print('asset id: ',cpe)

                        element = [cpe, cve_id, created_at, None]
                        add_list.append(element)
                    # print('Number of new vulnerable assets matched: ', len(cpe_list))  # debugging
                # for v in add_list:
                #     print(v)

                # q.add_multiple_client_vulnerable_asset(add_list, cursor) # match with the  collect from NVD/vulDB separately

                # insert vulnerable assets matched into temp_vul_asset table
                if len(add_list) > 0:
                    add_multiple_temp_vulnerable_asset(add_list,cursor)
                    connection.commit()
                msg = f"""there are {len(add_list)} clients's cpe affected by new vulnerabilities"""
                debug_log('info', msg)
                # print(' ')

            msg = f"""{added_cve} CVEs has been added to the DB"""
            debug_log('info', msg)


    except mysql.connector.Error as error:
        print("Failed in match_cve_client_cpe {}".format(error))
        msg = 'Failed in match_cve_client_cpe(): ' + str(error)
        debug_log('error',msg)

    finally:
        """ Get execution time of the function"""
        end_time = time.time()
        exec_time = end_time - start_time
        print('match_cve_client_cpe execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
        debug_log('debug','End match_cve_client_assets()')
        # return the date so we can get the lastet inserted records
        # return (created_at) # match with the  collect from NVD/vulDB separately


""" Get the list of clients concerned by the newest vulnerabilities and their vulnerable assets """
def match_client_vuln_assets(connection,last_vuln_assets):
    debug_log('debug','Start match_client_vuln_assets()')
    client_assets_list = []
    try:
        # Insert the last collected vulnerable assets into client_vuln_asset table
        cursor = connection.cursor(dictionary=True,buffered=True)
        now = datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")
        add_list = []
        # print('\nList of vulnerable assets matched with client assets:') # debugging
        """ Adding matched cpes to client_vulnerable_asset_table"""
        for a in last_vuln_assets:
            # print(a) # debugging
            element = [a['cpe'], a['cve'], created_at, None]
            add_list.append(element)
        add_multiple_client_vulnerable_asset(add_list,cursor)
        connection.commit()

        print('\nGetting the list of vulnerable assets per client...')
        start_time = time.time()  # to calculate execution time


        # print('number of vulnerable assets: ', len(last_vuln_assets))
        selected_records = [] # list of clients and their vulnerable assets (for alerts)
        tickets_list = [] # list of tickets: ['cve':'','list_usages':[id1,id2,...]]
        for i in last_vuln_assets:
            select_Query = """ select au.id, a.asset_ref, a.responsable, a.groupe, au.status from asset_usage au, asset a where au.asset_id =a.id and au.cpe = %s """
            # print('\n select_query: ',select_Query)
            # print('cpe arg in the query: ',i['asset'])
            query_arg = (i['cpe'],)
            # print('query_arg: ',query_arg)
            cursor.execute(select_Query, query_arg)
            records = cursor.fetchall()
            # print('records: ',records)
            if records:  # there is vulnerable assets used by the client (this check is made to avoid errors)
                selected_records.append({'cpe':i,'records':records})
                # print('\cpe arg in the query: ', i['cpe'])
                # print('cpe is affected to group id ',records)
                # print('number of records selected: ', len(records))
                """ Get the list of clients and their vulnerable assets"""
                """ Build the list of tickets """
                for c in records:  # list of client_group id
                    """ Check if an alert was sent to the client for the cve_vuln_asset """
                    select_query = """ select aut_alert from usage_aut_alert where usage_id = %s and cve = %s """
                    usage_alert_arg = (c['id'], i['cve'])
                    # print('select aut_alert query arg: ',usage_alert_arg)
                    cursor.execute(select_query, usage_alert_arg)
                    alert_id = cursor.fetchone()
                    # print('alert_id: ', alert_id)
                    if not alert_id:  # there is no alert for this cpe/cve
                        # print('\n There is a vulnerable asset non alerted: ',i) # debugging
                        # print(c) # debugging
                        """ check if the client exists in the list"""
                        if any(dict.get('client') == c['groupe'] for dict in client_assets_list):  # the client id alredy exist in the list
                            # if c['status'] != 2:  # 2 : asset vulnerable alerted
                            """ Adding the cpe in the list of vulnerable assets of the client """
                            # print('Adding vulnerable asset to the list of the client ',c['groupe'])
                            for d in client_assets_list:  # lookin for the client in the list client_asset_list
                                if d['client'] == c['groupe']:
                                    exist = False
                                    for v in d['asset_cve_list']:
                                        # print('asset_cve_list elemnt: ',type(v))
                                        if i['cpe'] == v['cpe']:  # check if the cpe exists in the client_asset_list
                                            exist = True
                                            if c['asset_ref'] not in v['ref_list']:
                                                v['ref_list'].append(c['asset_ref'])
                                            # checking if the cve already exists in the cve_list of the asset with alert
                                            cve_in_list = False
                                            for cve in v['cve_list']:
                                                if i['cve'] == cve['id_cve']:
                                                    cve_in_list = True
                                                    break
                                            if not cve_in_list: # the CVE does not exist in the cve_list
                                                cve_elem = {'id_cve': i['cve'], 'links': i['links'],'cvss2':i['cvss2'],'cvss3':i['cvss3']}
                                                v['cve_list'].append(cve_elem)
                                            # if i['cve'] not in v['cve_list']:  # old configuration
                                            #     v['cve_list'].append(i['cve'])

                                            if i['links'] not in d['links']:
                                                d['links'].append(i['links'])
                                            break
                                    if not exist:  # the cpe does not exists in the asset_cve_list
                                        cve_elem = {'id_cve':i['cve'],'links':i['links'],'cvss2':i['cvss2'],'cvss3':i['cvss3']}
                                        cve_list = [cve_elem]
                                        # cve_list = [i['cve']]
                                        ref_list = [c['asset_ref']]
                                        asset_cve_list = {'cpe': i['cpe'],'ref_list': ref_list, 'cve_list': cve_list}
                                        d['asset_cve_list'].append(asset_cve_list)  # add the vulnerable asset/cve into the asset_cve_list

                        else:  # the client id does't exist in the list
                            # if c['status'] != 2: # 2 : asset vulnerable alerted
                            # print('Adding new client to the alerting list')
                            cve_elem = {'id_cve': i['cve'], 'links':i['links'],'cvss2':i['cvss2'],'cvss3':i['cvss3']}
                            cve_list = [cve_elem]
                            # cve_list = [i['cve']] # old configuration (cve list containing list of cve ids)
                            cpe = i['cpe']
                            ref_list = [c['asset_ref']] # list of assets_ref including cpes's id
                            asset_cves_element = {'cpe': cpe, 'ref_list':ref_list, 'cve_list': cve_list}
                            asset_cve_list = [asset_cves_element]
                            links = [i['links']]

                            dict_elem = {'client': c['groupe'], 'responsable': c['responsable'], 'asset_cve_list': asset_cve_list, 'links': links}
                            client_assets_list.append(dict_elem)
                            # print('client_asset_list initialized: \n', client_assets_list)

                    """ Creating pre_tickets for matched cpes"""
                    """ Check if there is already a pre_ticket for the cve/usage """
                    select_query = """ select id from pre_ticket where usage_id = %s and cve = %s """
                    ticket_arg = (c['id'], i['cve']) # (usage_id,cve_id)
                    # print('select aut_alert query arg: ',usage_alert_arg)
                    cursor.execute(select_query, ticket_arg)
                    ticket_id = cursor.fetchone()
                    # print('alert_id: ', alert_id)
                    if not ticket_id: # there is no pre_ticket for the usage/cve
                        cve_in_tickets = False
                        for ticket in tickets_list:
                            if ticket['cve'] == i['cve']: # find the cve in the tickets list
                                cve_in_tickets = True
                                ticket['usages_list'].append(c['id']) # add the usage id to the usages list the ticket
                                break
                        if not cve_in_tickets: # there no cve entry in the tickets_list
                            ticket_elem = {'cve':i['cve'],'usages_list':[c['id']]}

                            tickets_list.append(ticket_elem)  # adding the cve entry to the ticket_list

        """ # Adding tickets to the DB (pre_ticket table) """
        insert_tickets_from_list(connection,tickets_list)
        # connection.commit()
        # print('matched assets/client: ')
        # for sr in selected_records:
        #     print(sr)
        print('\nClient_assets_list lenght: ', len(client_assets_list))
        # for c in client_assets_list:
        #     print('client: ',c['client'])
        #     for a in c['asset_cve_list']:
        #         print(a)

        """Delete collected assets from temp_vuln_assets"""
        clear_temp_vuln_assets(connection) # remove all entries from temp_vuln_assets table

        """ Get execution time of the function"""
        end_time = time.time()
        exec_time = end_time - start_time
        print('match_client_vuln_assets execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))

        """ return a list of dictionary that contains all client, their vulnerable assets and the references to the cve"""
        return client_assets_list

    except mysql.connector.Error as error:
        msg = 'Failed in match_client_vuln_assets(): ' + str(error)
        debug_log('error',msg)
        print("Failed in match_client_vuln_assets {}".format(error))
    finally:
        debug_log('debug','End match_client_vuln_assets()')
        return client_assets_list
