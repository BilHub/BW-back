""" This module is created for thetest v0.1 of PGV, it aims to manipulate api_key and credits of the vulbd accounts in the DB"""
from database.connection import connect_to_db, close_connection
from debug.debug import debug_log



""" Adding vuldb account """
def add_vuldb_account(record):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO vuldb_account (login, api_key, credit, mail) 
                                    VALUES (%s, %s, %s, %s) """

        recordTuple = (record['login'],record['api_key'],record['credit'],record['mail'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        if (cursor.rowcount>0):
            msg = f""" {record['login']} has been added to the database"""
            debug_log('info', msg)
        # print(cursor.rowcount," record inserted successfully into vuldb_account table")

    except Exception as error:
        msg = 'Failed in add_vuldb_account(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into vuldb_account table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)


""" Getting the api key of the account that has the maximum of credit (used for the test v0.1 of PGV)"""
def get_api_key(connection=None):
    api_key = None
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select api_key from vuldb_account where credit = (select max(credit) from vuldb_account)"
        cursor.execute(select_Query)
        record = cursor.fetchone()
        if record:
            api_key = record['api_key']
        msg = 'Api key selected : ' + str(api_key)
        debug_log('info', msg)
    except Exception as error:
        msg = 'Failed in get_api_key(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get api_key {}".format(error))

    finally:
        # if (connection.is_connected()):
        #     cursor.close()
        #     close_connection(connection)
        return api_key  # int


""" Updating credits of the account after the collect from vuldb"""
def update_credit(api_key,new_credit,connection=None):
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor()
        update_query = """UPDATE  ignore vuldb_account SET credit = %s where api_key = %s"""
        # print('cve_record',record)
        recordTuple = (new_credit, api_key)
        cursor.execute(update_query, recordTuple)
        connection.commit()
        if (cursor.rowcount>0):
            msg = f""" {new_credit} remaining for the account"""
            debug_log('info', msg)
        # print(cursor.rowcount, " credit updated updated successfully ")
    except Exception as e:
        msg = 'Failed in update_credit(): ' + str(e)
        debug_log('error', msg)
