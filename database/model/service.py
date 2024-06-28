import mysql.connector
from database.connection import connect_to_db, close_connection
import time
from debug.debug import debug_log



""" Add service """
def add_service(record,cursor):
    try:
    #     connection = connect_to_db()
    #     cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO service (name,  manager) 
                                        VALUES (%s, %s) """

        recordTuple = (record['name'], record['manager'])
        cursor.execute(insert_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into asset_usage table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_service(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into serice table {}".format(error))
    #
    # finally:
    #     if (connection.is_connected()):
    #         cursor.close()
    #         colse_connection(connection)
    #         print("MySQL connection is closed")


""" Modify service's manager """
def update_service(record,cursor):
    try:
    #     connection = connect_to_db()
    #     cursor = connection.cursor()
        update_query = """UPDATE IGNORE  service set manager = %s where id = %s """

        recordTuple = (record['manager'], record['id'])
        cursor.execute(update_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into asset_usage table")
    except mysql.connector.Error as error:
        msg = 'Failed in update_service(): ' + str(error)
        debug_log('error', msg)
        # print("Failed to modify service's manager {}".format(error))