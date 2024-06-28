import mysql.connector
from mysql.connector import Error, errorcode
from debug.debug import debug_log

""" Open connection to Database"""

def connect_to_db():
    """ Connect to user MySQL database """
    conn = None
    # debug_log('connecting to the database ...')
    try:
        # print('Triying to connect to mysql database') #debug
        conn = mysql.connector.connect(host='localhost',
                                       database='pgvdb_schema5',
                                       user='scout',
                                       password='2.PGV_db')

    except Error as e:
        msg = 'Failed in send_mime_mail(): ' + str(e)
        debug_log('error',msg)
        print(e)
    finally:
        return conn


""" Colse connection to Database"""
def close_connection(connection):
    if connection.is_connected():
        connection.close()
