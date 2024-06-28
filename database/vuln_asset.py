import mysql.connector
# from database.connection import connect_to_db, close_connection
import time
from debug.debug import debug_log

"""" Adding record to vulnerable_asset table (USELESS)"""
# def add_vulnerable_asset(record,cursor):
#     try:
#         # connection = connect_to_db()
#         # cursor = connection.cursor()
#         insert_query = """INSERT IGNORE INTO vulnerable_asset (asset, cve, title, description, links, date, score, mitigations, workarounds, cvss2, cvss3)
#                         VALUES (  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
#         # print('vulnerable_asset_record',record)
#         recordTuple = (record['asset'],record['cve'],record['title'],record['description'],record['links']
#                        ,record['date'],record['score'],record['mitigations'],record['workarounds'],record['cvss2'],record['cvss3'])
#         cursor.execute(insert_query, recordTuple)
#         # connection.commit()
#         # print(cursor.rowcount," record inserted successfully into vulnerable_asset table")
#     except mysql.connector.Error as error:
#         msg = 'Failed in add_vunerable_asset(): ' + str(error)
#         debug_log('error', msg)
#         print("Failed to insert into vulnerable asset table {}".format(error))
#     #
#     # finally:
#     #     if (connection.is_connected()):
#     #         cursor.close()
#     #         colse_connection(connection)
#     #         print("MySQL connection is closed")



""" Adding multiple records to client_vulnerable_asset table """
def add_multiple_client_vulnerable_asset(records_list,cursor):
    debug_log('debug','Start add_multiple_client_vulnerable_asset()')
    try:
    # if 1==1: # debbuging
        print('\nAdding client vulnerable assets...')
        # insert_query = """INSERT IGNORE INTO vulnerable_asset (item, asset, cve, title, description, links, date, score, mitigations, workarounds,cvss2,cvss3)
        #                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        insert_query = """INSERT IGNORE INTO client_vulnerable_asset (cpe, cve,  date, score) 
                        VALUES (%s, %s, %s, %s) """
        # print('client_vulnerable_asset records: ')
        recordTuple = []
        for i in records_list:
            # print(i)
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        print(cursor.rowcount," record inserted successfully into client_vulnerable_asset table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_multiple_client_vulnerable_asset(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple client_vulnerable_asset {}".format(error))
    finally:
        debug_log('debug','End add_multiple_client_vulnerable_asset()')


""" Adding multiple temp_vulnerable_asset """
def add_multiple_temp_vulnerable_asset(records_list,cursor):
    debug_log('debug','Start add_multiple_temp_vulnerable_asset()')
    try:
    # if 1==1: # debbuging
        print('\nAdding temp vulnerable assets...')
        insert_query = """INSERT IGNORE INTO temp_vulnerable_asset (cpe, cve,  date, score) 
                        VALUES (%s, %s, %s, %s) """
        # print('client_vulnerable_asset records: ')
        recordTuple = []
        for i in records_list:
            # print(i)
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        count = cursor.rowcount
        msg = f"""{count} records inserted successfully into temp_vulnerable_asset table"""
        debug_log('info', msg)
        print(count," record inserted successfully into temp_vulnerable_asset table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_multiple_temp_vulnerable_asset(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple temp_vulnerable_asset {}".format(error))
    finally:
        debug_log('debug','End add_multiple_temp_vulnerable_asset()')

""" get the last inserted vulnerable assets in temp_vuln_assets table (return a dictionary list ([{'asset': ....,....}])) """
def get_temp_vuln_assets_records(connection):
    debug_log('debug','Start get_temp_vuln_assets_records()')
    print('\nGetting the last collected vulnerable_assets that match with client assets...')
    start_time = time.time()  # to calculate execution time

    select_Query = """ select cpe, cve, links, cvss2, cvss3 from temp_vulnerable_asset, cve_temp where temp_vulnerable_asset.cve = cve_temp.id """
    # select_Query = """ select asset, cve, links, cvss2, cvss3 from client_vulnerable_asset, cve_temp where client_vulnerable_asset.cve = cve_temp.id """ ## test send alerts

    cursor = connection.cursor(dictionary=True,buffered=True)
    # cursor = connection.cursor()
    cursor.execute(select_Query)
    records = cursor.fetchall()

    print('Number of last inserted vulneravble assets: ',len(records))
    # print('records: \n',records)
    # for d in records:
        # print('type of the record selected: ',type(d))
        # print(d['asset'])
        # print(d)
    cursor.close()

    """ Get execution time of the function"""
    end_time = time.time()
    exec_time = end_time - start_time
    print('get_temp_vuln_assets_records execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)),'\n')
    debug_log('debug','End get_temp_vuln_assets_records()')
    """ Return a list of cpe_id/cve_id/links to cve of the last added cpes client_vulnerable_asset """
    return records



""" clear temp_vulnerable_asset table"""
def clear_temp_vuln_assets(connection):
    debug_log('debug','Start clear_temp_vuln_assets')
    print('\nDeleting temporaire vulnerable assets...')
    try:
        cursor = connection.cursor()
        delete_query = """ delete from temp_vulnerable_asset """
        cursor.execute(delete_query)
        connection.commit()

    except mysql.connector.Error as error:
        msg = 'Failed in clear_temp_vuln_assets(): ' + str(error)
        debug_log('error',msg)
        print("Failed to delete multiple temp vlnerable_assets {}".format(error))
    finally:
        debug_log('debug','End clear_temp_vuln_assets')


""" Adding multiple records to vulnerable_asset table"""
def add_multiple_vulnerable_asset(records_list,cursor):
    debug_log('debug','Start add_multiple_vulnerable_asset()')
    try:
        print('\nAdding vulnerable assets...')
        # insert_query = """INSERT IGNORE INTO vulnerable_asset (item, asset, cve, title, description, links, date, score, mitigations, workarounds,cvss2,cvss3)
        #                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        insert_query = """INSERT IGNORE INTO vulnerable_asset (asset, cve,  date, score) 
                        VALUES (%s, %s, %s, %s) """
        tuples = []
        for i in records_list:
            tuples.append((i))
        # print('recordTuple: ',tuples) # debug
        cursor.executemany(insert_query, tuples)
        # connection.commit()
        count = cursor.rowcount
        msg = str(count) + 'record inserted successfully into vulnerable_asset table'
        debug_log('debug',msg)
        print(cursor.rowcount," record inserted successfully into vulnerable_asset table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_multiple_vulnerable_asset(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple vulnerable_asset {}".format(error))
    finally:
        debug_log('debug','End add_multiple_vulnerable_asset()')


""" Adding multiple records to vulnerable_asset_archive table"""
def add_multiple_vulnerable_asset_archive(records_list,cursor):
    debug_log('debug','Start add_multiple_vulnerable_asset_archive()')
    start_time = time.time()
    try:
        print('\nAdding vulnerable assets to archive...')
        insert_query = """INSERT IGNORE INTO vulnerable_asset_archive (asset, cve,  date, score) 
                        VALUES (%s, %s, %s, %s) """
        # print('vulnerable_asset_record',record)
        recordTuple = []
        for i in records_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        print(cursor.rowcount," record inserted successfully into vulnerable_asset_archive table")


    except mysql.connector.Error as error:
        msg = 'Failed in add_multiple_vulnerable_asset(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple add_multiple_vulnerable_asset_archive() {}".format(error))

    finally:
        end_time = time.time()
        exec_time = end_time - start_time
        print('\nAdd vulnerable_asset_archive execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
        debug_log('debug','End add_multiple_vulnerable_asset_archive()')