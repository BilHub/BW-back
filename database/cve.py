import mysql.connector
from database.connection import connect_to_db, close_connection
from debug.debug import debug_log


class CVE:
    def __init__(self, **cve_dict):
        self.id = cve_dict['id']
        self.title = cve_dict['title']
        self.description = cve_dict['description']
        self.links = cve_dict['links']
        self.published_at = cve_dict['published_at']
        self.last_modified = cve_dict['last_modified']
        self.cvss2 = cve_dict['cvss2']
        self.cvss3 = cve_dict['cvss3']
        self.mitigations = cve_dict['mitigations']
        self.workarounds = cve_dict['workarounds']
        self.vuln_cpes = cve_dict['vuln_cpes'] # list of cpe_id
        self.temp = cve_dict['temp'] # boolean :if true the record is for cve_temp_table else for cve table



""" Functions """
""" Adding records to cve_temp table """
def add_multiple_cve_temp(cursor, cves_list):
    debug_log('debug','Start add_multiple_cve_temp')
    print('\nAdding CVE to cve_temp...')
    try:
        insert_query = """INSERT IGNORE INTO cve_temp (id, title, description, links, published_at, cvss3, mitigations, workarounds, last_modified, cvss2) 
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('cve_record',record)
        recordTuple = []
        print('number of cves to add: ', len(cves_list))
        # print('type of cve list: ', type(cves_list))
        # print('first element of the list: ', cves_list[0])
        for i in cves_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        print(cursor.rowcount, " record inserted successfully into cve_temp table")
        return cursor.rowcount

    except mysql.connector.Error as error:
        msg = 'Failed in add_multiple_cve(): ' + str(error)
        debug_log('error', msg)
        print("Failed to add multiple cve_temp {}".format(error))
    finally:
        debug_log('debug','End add_multiple_cve_temp')

""" Adding records to cve table """
""" Add only one cve record """
def add_cve(record, cursor):
    try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO cve (id, title, description, links, published_at, score, mitigations, workarounds, last_modified, cvss2) 
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('cve_record',record)
        recordTuple = (record['id'], record['title'], record['description'], record['links']
                       , record['published_at'], record['cvss3'], record['mitigations'], record['workarounds']
                       , record['last_modified'], record['cvss2'])
        cursor.execute(insert_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into cve table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_cve(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into cve table {}".format(error))
    #
    # finally:
    #     if (connection.is_connected()):
    #         cursor.close()
    #         colse_connection(connection)
    #         print("MySQL connection is closed")

""" Add many CVEs record at once """
def add_multiple_cve(cursor, cves_list):
    print('\nAdding CVE...')
    try:
        insert_query = """INSERT IGNORE INTO cve (id, title, description, links, published_at, cvss3, mitigations, workarounds, last_modified, cvss2) 
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('cve_record',record)
        recordTuple = []
        print('number of cves to add: ', len(cves_list))
        # print('type of cve list: ', type(cves_list))
        # print('first element of the list: ', cves_list[0])
        for i in cves_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        print(cursor.rowcount, " record inserted successfully into cve table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_multple_cve(): ' + str(error)
        debug_log('error', msg)
        print("Failed to add multiple cve {}".format(error))



""" Updating CVE """
""" Update one cve record"""
def update_cve(record,cursor):
    # try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        update_query = """UPDATE  ignore cve SET description = %s, links = %s, cvss3 = %s, mitigations = %s, 
                        workarounds = %s, last_modified = %s, cvss2 = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = (record['description'],record['links'],record['cvss3'],record['mitigations']
                       ,record['workarounds'],record['last_modified'],record['cvss2'],record['id'])
        cursor.execute(update_query, recordTuple)

""" Update multiple cve records """
def update_multiple_cve(cves_list, cursor):
    print('\nUpdating CVE...')
    try:
        update_query = """UPDATE  ignore cve SET description = %s, links = %s, cvss3 = %s, mitigations = %s, 
                           workarounds = %s, last_modified = %s, cvss2 = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = []
        print('number of cves to be updated: ', len(cves_list))
        # print('type of cve list: ',type(cves_list))
        # print('first element of the list: ',cves_list[0])
        for i in cves_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(update_query, recordTuple)
        print(cursor.rowcount, " record updated successfully into cve table")
    except mysql.connector.Error as error:
        msg = 'Failed in updae_multiple_cve(): ' + str(error)
        debug_log('error', msg)
        print("Failed to update multiple cve {}".format(error))

""" set a default value to last_modified column """
def update_cve_last_modified():
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        update_query = """UPDATE ignore cve SET last_modified = published_at where last_modified is null"""
        cursor.execute(update_query)
        print(cursor.rowcount, " cve last_modified date updated successfully ")
    except mysql.connector.Error as error:
        msg = 'Failed in update_cve_last_modified(): ' + str(error)
        debug_log('error', msg)
        print("Failed to update cve table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")

""" Calculate the personalised score of the cve according to the importance of the asset """
def calculate_final_score(connection,cve_id,asset_usage_id): # this version return the CVSS V3 score of the CVE as the final score
    score = None
    try:
        cursor = connection.cursor(dictionary=True, buffered=True)
        select_cve_query = """select cvss2, cvss3 from cve_temp where id = %s"""
        cve_arg = (cve_id,)
        cursor.execute(select_cve_query,cve_arg)
        cve_scores = cursor.fetchone()
        temp_cvss3 = cve_scores['cvss3']

        select_importance_query = """ select a.importance from   asset a 
                                    left join asset_usage a_u on  a_u.asset_id = a.id 
                                    where a_u.id = %s """
        usage_arg = (asset_usage_id,)
        cursor.execute(select_importance_query, usage_arg)
        importance_record = cursor.fetchone()
        importance = importance_record['importance']

        if temp_cvss3 and importance:
            score = (temp_cvss3 * importance)/3 # formulat of the final score
            if score > 10:
                score = 10
    except mysql.connector.Error as error:
        msg = 'Failed in calculate_final_score(): ' + str(error)
        debug_log('error', msg)
        print("Failed to calculate cve personalised score {}".format(error))
    finally:
        return score

""" Deletting CVEs from cve_temp table """
def drop_multiple_cve_temp(connection,delete_list):
    print('\nDeleting CVEs from cve_temp...')
    try:
        cursor = connection.cursor(dictionary=True, buffered=True)
        for cve_id in delete_list:
            delete_query = """ delete from cve_temp where id = %s"""
            query_arg = (cve_id,)
            cursor.execute(delete_query, query_arg)
            connection.commit()

    except mysql.connector.Error as error:
        msg = 'Failed in drop_multiple_cve_temp(): ' + str(error)
        debug_log('error', msg)
        print("Failed to delete multiple cve_temp {}".format(error))

""" Migrate the collected CVE of the day (week or month) from cve_temp to cve table"""
def purge_cve_temp():
    try:
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)

        select_Query = """ select * from cve_temp ct where not exists (select cve from client_vulnerable_asset cva where ct.id = cva.cve) """
        # print('select query: ',select_Query)
        cursor.execute(select_Query)
        records = cursor.fetchall()
        print('number of CVEs selected from cve_temp: ', len(records))
        # rec = list(records[0].values())
        # print('First record: \n',rec[1:-1])
        add_list = []
        delete_list = []
        for r in records:
            # print(r)
            delete_list.append(r['id'])
            rec = list(r.values())
            add_list.append(rec)
            # print(rec)
            # break
        """ Adding selected records to cve table without updating"""
        add_multiple_cve(cursor,add_list)
        connection.commit()

        """ Deleting selected CVEs from cve_temp table """
        drop_multiple_cve_temp(connection,delete_list)

    except mysql.connector.Error as error:
        msg = 'Failed in purge_cve_temp(): ' + str(error)
        debug_log('error', msg)
        print("Failed to transfer cves {}".format(error))

    finally:
        if (connection.is_connected()):
            connection.commit()
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")