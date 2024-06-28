import mysql.connector
from database.connection import connect_to_db, close_connection
import time
from debug.debug import debug_log


class Asset:
    def __init__(self, **assset_dict):
        self.asset_ref = assset_dict['asset_ref']
        self.client = assset_dict['client']
        self.status = assset_dict['status']
        self.modified = assset_dict['modified']
        self.importance = assset_dict['importance']
        self.assets = assset_dict['assets']
        # self.cves = cves # not sure??


class CPE:
    def __init__(self, **cpe_dict):
        self.id_cpe = cpe_dict['id_cpe']
        self.type = cpe_dict['type']
        self.producer = cpe_dict['producer']
        self.neme = cpe_dict['name']
        self.version = cpe_dict['version']
        self.links = cpe_dict['links']


""" Adding asset_type (USELESS)"""
# def add_asset_type(record):
#     try:
#         debug_log('debug', 'Start add_asset_type')
#         connection = connect_to_db()
#         cursor = connection.cursor()
#         insert_query = """INSERT IGNORE INTO asset_type (id, description, sub_type) VALUES (%s, %s, %s) """
#
#         recordTuple = (record['id'],record['description'],record['sub_type'])
#         cursor.execute(insert_query, recordTuple)
#         connection.commit()
#         print(cursor.rowcount," record inserted successfully into asset_type table")
#
#     except mysql.connector.Error as error:
#         print("Failed to insert into asset_type table {}".format(error))
#         msg = 'Failed to insert into asset_type table: ' + str(error)
#         debug_log('error', msg)
#
#     finally:
#         if (connection.is_connected()):
#             cursor.close()
#             close_connection(connection)
#             # print("MySQL connection is closed")
#             debug_log('debug', 'End add_asset_type')

""" Adding record to cpe table """
def add_cpe(record,cursor):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """ INSERT IGNORE INTO cpe (id_cpe, type, producer, name, version) 
        VALUES (%s, %s, %s, %s, %s) """

        recordTuple = (record['cpe_id'],record['type'],record['producer'],record['name'],record['version'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into cpe table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_cpe(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into cpe table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")


""" Adding multiple records to asset table"""
def add_multiple_cpe(cursor,asset_list):
    try:
        print('\nAdding CPEs ...')
        debug_log('debug', 'Start add_multiple_asset')
        start_time = time.time()
        insert_query = """INSERT IGNORE INTO cpe (id_cpe, type, producer, name, version) 
                    VALUES (%s, %s, %s, %s, %s) """
        # print('item_record',item_record)
        recordTuple = []
        for i in asset_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        print('multiple cpe inserted in the DB')
        # connection.commit()
        print(cursor.rowcount, " record inserted successfully into asset table")
        end_time = time.time()
        exec_time = end_time - start_time
        print('\nadd_multiple_cpe execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
    except Exception as error:
        msg = 'Failed in add_multiple_cpe(): ' + str(error)
        debug_log('error', msg)
    finally:
        debug_log('debug', 'End add_multiple_cpe')



""" Update asset (producer, name and version)"""
def update_cpe(cursor,record):
    try:
        # print('\nUpdating assets ...')
        update_query = """UPDATE IGNORE  cpe set  producer = %s, name = %s, version = %s 
                    where id_cpe = %s """
        # print('item_record',item_record)
        recordTuple = (record['producer'], record['name'], record['version'], record['id_cpe'])
        cursor.execute(update_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount, " asset updated successfully ")
    except mysql.connector.Error as error:
        msg = 'Failed in update_cpe(): ' + str(error)
        debug_log('error', msg)
        print("Failed to update cpe {}".format(error))


""" Add multiple records to client_assets table """
def add_multiple_client_cpe(cpe_list,connection=None):
    try:
        if not connection:
            connection = connect_to_db()
        cursor = cursor = connection.cursor(dictionary=True, buffered=True)
        print('\nAdding client_assets ...')
        start_time = time.time()
        insert_query = """INSERT IGNORE INTO client_cpe (id_cpe, type, producer, name, version) 
                        VALUES (%s, %s, %s, %s, %s) """
        # print('item_record',item_record)
        recordTuple = []
        for i in cpe_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # print('multiple cleint_assets inserted in the DB')
        connection.commit()
        count = str(cursor.rowcount)
        msg = f""" {count} inserted in client_cpe table"""
        debug_log('debug', msg)
        print(count, " record inserted successfully into client_cpe table")
        end_time = time.time()
        exec_time = end_time - start_time
        print('\nadd_multiple_client_cpe execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)))
    except Exception as error:
        msg = 'Failed in add_multiple_client_cpe(): ' + str(error)
        debug_log('error', msg)
        print("Failed to add multiple client cpe  {}".format(error))


def cpe_search():
    try:
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)
        producer = input('Editeur du produit : ') + '%'
        name = input('Nom du produit : ') + '%'
        version = input('Version : ') + '%'
        select_Query = "select id_cpe from cpe where producer like %s and name like %s and version like %s"
        arg = (producer.lower(), name.lower(), version)
        cursor.execute(select_Query, arg)
        records = cursor.fetchall()
        print('\n', len(records), ' cpe trouvés')
        for i in records:
            print(i)
    except Exception as error:
            msg = 'Failed in cpe_search(): ' + str(error)
            debug_log('error', msg)
    finally:
        close_connection(connection)


""" Add asset """
def add_asset(record,cursor):
    try:
    #     connection = connect_to_db()
    #     cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO asset (asset_ref, groupe, status, modified, importance, manager, service) 
                                        VALUES (%s, %s, %s, %s, %s, %s, %s) """

        recordTuple = (record['asset_ref'], record['group'], record['status'], record['modified'], record['importance'], record['manager'], record['service'])
        cursor.execute(insert_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into asset_usage table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_asset(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into asset table {}".format(error))
    #
    # finally:
    #     if (connection.is_connected()):
    #         cursor.close()
    #         colse_connection(connection)
    #         print("MySQL connection is closed")


""" Add multiple assets """
def add_multi_asset(records,connection=None):
    count = 0
    try:
        debug_log('debug', 'Start add_multi_asset()')
        if not connection:
            connection = connect_to_db()
        else:
            connection = connect_to_db() # debug
            # print('connection is OK') # debug
        cursor = connection.cursor()
        recordTuple = []
        for i in records:
            recordTuple.append((i))
        insert_query = """INSERT IGNORE INTO asset (asset_ref, groupe, status, modified, importance, manager, service, responsable) 
                                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) """

        cursor.executemany(insert_query, recordTuple) # records are already initied in the parent function (add_assets_to_client)
        connection.commit()
        count = int(cursor.rowcount)
        # print(cursor.rowcount," record inserted successfully into asset table")
    except Exception as error:
        msg = 'Failed in add_multi_asset(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into asset table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            debug_log('debug', 'End add_multi_asset()')
        if count >= 0:
            return count
        else:
            return 0

