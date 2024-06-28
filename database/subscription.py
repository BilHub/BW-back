import mysql.connector
from debug.debug import debug_log
from database.connection import connect_to_db
from database.cve import calculate_final_score
from datetime import datetime



""" Create new subscription """
def add_subscription(record,connection=None):
    debug_log('debug','Start add_subscription')
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)
        insert_query = """INSERT IGNORE INTO subscription (type, start_a, expire_on, status) 
                                        VALUES (%s, %s, %s, %s) """
        # print('aut_alert record: \n',record)
        recordTuple = (record['type'],record['start_a'],record['expire_on'], record['status'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into subscription table")
    except mysql.connector.errors as error:
        msg = 'Failed in add_subscription(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End add_subscription')


""" Update the subscription expiring date """
def extend_subscription(id,new_expiring_date,cursor):
    debug_log('debug','Start extend_subscription')
    try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        update_query = """UPDATE  ignore subscription SET  expire_on = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = (new_expiring_date, id)
        cursor.execute(update_query, recordTuple)
        print(cursor.rowcount, " subscription updated successfully ")
    except mysql.connector.errors as error:
        msg = 'Failed in extend_subscription(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End extend_subscription')


""" Create new subscription plan (type)"""
def add_subs_plan(record,connection=None):
    debug_log('debug','Start add_subs_plan')
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)
        insert_query = """INSERT IGNORE INTO subs_plan (name, user_credits, cpe_ctredits, payement) 
                                        VALUES (%s, %s, %s, %s) """
        # print('aut_alert record: \n',record)
        recordTuple = (record['name'],record['user_credits'],record['cpe_ctredits'], record['payement'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into subs_plan table")
    except mysql.connector.errors as error:
        msg = 'Failed in add_subs_plan(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End add_subs_plan')
