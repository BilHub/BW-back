""" This module contains functions that match vulnerable cpes with the all cpes contained in NVD cpe dictinary. This functions are used by the module collectore.store_vulnerabilities.py """



from datetime import datetime
import time
from natsort import natsorted
from operator import itemgetter
import mysql.connector
from database.vuln_asset import add_multiple_vulnerable_asset
from debug.debug import debug_log



""" 4 Getting the index of the element with the specific version in the dictionary {cpe_id, version}"""
def find_version_index(list, version): ### Obsolètte
    # print(version)
    for i, dic in enumerate(list):
        # print(dic)
        if dic['version'] == version:
            return i
    return -1


""" remove special beckslash-special_chars from the cpe id """
def remove_schars(cpe_id):
    cpe_id = cpe_id.replace('\:', '()')
    cpe_id = cpe_id.replace('\\', '')
    return cpe_id


def get_nvd_cpe_list(cursor,cpe): # this function match with collect collect_nvd_*_cve and import_all_cves
    try:
        # print('\nget_nvd_cpe_list function: ')
        sorted_cpes = []
        cpe_arg = cpe.replace('*', '%')
        # print('\ncpe_arg: ',cpe_arg)
        select_Query = "select id_cpe, version from cpe where id_cpe like %s"
        arg = (cpe_arg,)
        cursor.execute(select_Query, arg)
        records = cursor.fetchall()
        # print('\nnumber of records selected for {} is: {}'.format(cpe_arg,len(records)))
        # for c in records:
        # print(c)
        if len(records) != 0:
            """ Sort the cpe list according to the version"""
            # print('len records befor sort: ',len(records))
            # print(type(records[0]))
            natsorted(records, key=itemgetter(*['version']))
            # print('len records after sort: ', len(records))
            sorted_cpes = records
        else:
            cpe_id = remove_schars(cpe)
            # print(i,':', cpe_id)
            cpe_elem = cpe_id.split(':')
            version = cpe_elem[-8].replace('()', ':')
            cpe_dict = {'id_cpe': cpe, 'version': version}  # add the id_cpe to the list of cpes
            sorted_cpes.append(cpe_dict)
        # print('sorted cpes:',len(sorted_cpes))

        # print('selected_cpes:\n', selected_cpes)
        # print('Sorted cpes: ')
        # i=0
        # for s in sorted_cpes:
        #     print(i,s)
        #     i = i+ 1

    except mysql.connector.Error as error:
        msg = 'Failed in get_nvd_cpe_list(): ' + str(error)
        debug_log('error', msg)
        print("Failed in get nvd cpe list: {}".format(error))

    finally:
            return sorted_cpes


""" 2 : Getting the specific range of th cpe matching list from the database"""
def cpe_match_from_db(cursor,cpe_list): # this function match with import_all_cve
    # print('cpe_list: ',cpe_list)
    final_cpe_list = []
    for i in cpe_list:
        # print('cpe_list element in function 2: ',i)
        if (i['range_id']):
            sorted_cpes = get_nvd_cpe_list(cursor,i['cpe_id']) # get_cpe_list has beed updated, the function's arg is a list
            start = 0
            end = len(sorted_cpes)
            # print('nb cpes selected from DB: ',len(sorted_cpes))
            # print('cpes selected from DB: ',sorted_cpes)
            # j=0
            # for c in sorted_cpes:
            #     print(j,' : ',c)
            #     j = j+ 1
            """ Get the right range start index"""
            if (i['rangeStartVersion'] != ''):

                start_index = find_version_index(sorted_cpes, i['rangeStartVersion'])
                if start_index != -1:
                    start = start_index
                    if (i['rangeStartType'] == 'excluding'):
                        # print('start excluding True')
                        start = start + 1

            """ Get the right range start index"""
            # print('rangeEndType: ',i['rangeEndType'])
            # print('rangeEndVersion: ',i['rangeEndVersion'])
            if (i['rangeEndVersion']):
                end_index = find_version_index(sorted_cpes, i['rangeEndVersion'])
                # print('end index: ',end_index)
                if (end_index != -1):
                    end = end_index
                    if (i['rangeEndType'] == 'including'):
                        # print('end including True')
                        end = end + 1

            # print('range start index: ', start, ' range end index: ', end)
            # print('final cpe matching list lenght: ', len(sorted_cpes[start:end]))
            i = 0
            for c in sorted_cpes[start:end]:
                final_cpe_list.append(c['id_cpe'])
                # print(c)
                # print(i)
                # i = i + 1
        else:
            final_cpe_list.append(i['cpe_id'])
        # break
    return final_cpe_list



""" adding the cpes into vulnerable_asset """
def match_cve_cpe(connection,vuln_asset_details_list): # list containing cve_details , cve_id, digest, cve_details (match with import_all_cve and collect_nvd(_optimized)_updated_cve)
    start_time = time.time() # to calculate execution time
    debug_log('debug', 'Start match_cve_cpe()')
    cursor = connection.cursor()
    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    print('lenght of vulnerable cpe details list: ',len(vuln_asset_details_list))
    if len(vuln_asset_details_list)>0:
        add_list = []
        # print('Getting cve details ...')
        # i = 0 # debugging
        for vuln_asset_details in vuln_asset_details_list:
            # i= i + 1 # debugging
            cve_id = vuln_asset_details['cve_id']
            # print('\ncve_id: ', cve_id)
            # print('lenght of initial vulnerable assets list: ',len(vuln_asset_details['vulnerable_assets']))
            # cpes_list = cd.get_cpe_list(vuln_asset_details['vulnerable_assets'])
            cpes_list = vuln_asset_details['vulnerable_assets']
            # print('cpe list lenght: ',len(cpes_list))
            # Getting  last_modified of the cve from the DB
            # connection = q.connect_to_db()
            # select_Query = "select id from item where digest = %s"
            # select_record = (vuln_asset_details['digest'],)
            # cve_cursor = connection.cursor()
            # cursor.execute(select_Query, select_record)
            # record = cursor.fetchone()
            # print('record selected from item: ',record)

            # if (record):
            for cpe in cpes_list:
                # print('Adding vulnerable_asset...')
                # print('asset id: ',cpe)
                element = [cpe, cve_id, created_at, None]
                add_list.append(element)
            # if i >= 5: # debugging
            #     break # to test one time only
        print('Number of final vulnerable assets affected by vulnerabilities: ', len(add_list))
        add_multiple_vulnerable_asset(add_list, cursor)
        connection.commit()
            # print(' ')
        """ Get execution time of the function"""
        end_time = time.time()
        exec_time = end_time - start_time
        print('match_cpe_cve execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
        debug_log('debug', 'Start match_cve_cpe()')

        # return the date so we can get the lastet inserted records

        # return (created_at)
    # else:
    #     return None

