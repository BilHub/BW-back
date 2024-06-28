import mysql.connector
from debug.debug import debug_log
from database.connection import connect_to_db



class Alert:
    def __init__(self, **alert_dict):
        self.id = alert_dict['id']
        self.title = alert_dict['title']
        self.message = alert_dict['message']
        self.links = alert_dict['links']
        self.created_at = alert_dict['created_at']
        self.status = alert_dict['status']
        self.solutions = alert_dict['solutions']
        self.published_on = alert_dict['published_on']
        self.score = alert_dict['score']
        self.client = alert_dict['client']
        self.assets = alert_dict['assets']
        # self.cves = cves # not sure??


""" Adding record to aut_alert table"""
def add_aut_alert(record,connection=None):
    debug_log('debug','Start add_aut_alert')
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)
        insert_query = """INSERT IGNORE INTO aut_alert (title, message, links, created_at, status, solutions, published_on, responsable) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) """
        # print('aut_alert record: \n',record)
        recordTuple = (record['title'],record['message'],record['links']
                       ,record['created_at'],record['status'],record['solutions'],record['published_on'], record['responsable'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into aut_alert table")
    except Exception as error:
        msg = 'Failed in add_aut_alert(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End add_aut_alert')


""" Update the published_on and status of the alert """
def update_aut_alert(id,published_on,status,cursor):
    debug_log('debug','Start update_aut_alert')
    try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        update_query = """UPDATE  ignore aut_alert SET published_on = %s, status = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = (published_on,status,id )
        cursor.execute(update_query, recordTuple)
        print(cursor.rowcount, " alert updated successfully ")
    except mysql.connector.errors as error:
        msg = 'Failed in update_aut_alert(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End update_aut_alert')

""" Adding record to usage_aut_alert table (link alert to asset_usage and cve_temp)"""
def add_usage_aut_alert(record,cursor):
    try:
    #     connection = connect_to_db()
    #     cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO usage_aut_alert (aut_alert, usage, cve) 
        VALUES (%s, %s, %s) """

        recordTuple = (record['aut_alert'],record['usage'],record['cve'])
        cursor.execute(insert_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into usage_aut_alert table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_usage_aut_alert(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into usage_aut_alert table {}".format(error))
    #
    # finally:
    #     if (connection.is_connected()):
    #         cursor.close()
    #         colse_connection(connection)
    #         print("MySQL connection is closed")

""" Adding multile records to usage_auth_alert table """
def add_multi_usage_aut_alert(records_list,cursor):
    debug_log('debug','Start add_multi_usage_aut_alert()')
    try:
        print('\nAdding usage_aut_alert ...')
        insert_query = """INSERT IGNORE INTO usage_aut_alert (aut_alert, usage_id, cve) 
                VALUES (%s, %s, %s) """
        # print('vulnerable_asset_record',record)
        recordTuple = []
        for i in records_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        # connection.commit()
        print(cursor.rowcount," record inserted successfully into usage_aut_alert table")
    except mysql.connector.Error as error:
        msg = 'Failed in send_alerts(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple usage_aut_alert {}".format(error))
    finally:
        debug_log('debug','End add_multi_usage_aut_alert()')

