import mysql.connector
from database.connection import connect_to_db, close_connection
from debug.debug import debug_log


""" Adding source """
def add_source(source_record):
    try:
        debug_log('debug','Start add_source()')
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO source (full_url, digest,url,host,mtbc,port,sourcename,category,language,enabled,use_keywords_matching,rating,type) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """

        recordTuple = (source_record['full_url'],source_record['digest'],source_record['url'],source_record['host']
                       ,source_record['mtbc'],source_record['port'],source_record['sourcename'],source_record['category']
                       ,source_record['language'],source_record['enabled'],source_record['use_keywords_matching'],source_record['rating'],source_record['type'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        count = cursor.rowcount
        print(count," record inserted successfully into source table")

        msg = str(count) + ' record inserted successfully into source table'
        debug_log('debug',msg)


    except mysql.connector.Error as error:
        msg = 'Failed in add_source(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into source table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")
            debug_log('debug', 'Start add_source()')

""" Update last collected date of the source (last_update) """
def update_source(id,date,create_entry, cursor):
    try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        update_query = """UPDATE  ignore source SET last_update = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = (date,id )
        cursor.execute(update_query, recordTuple)
        print(cursor.rowcount, " last_update date updated successfully ")
        update_query = """UPDATE  ignore source SET change_entry = %s where id = %s"""
        recordTuple = (create_entry, id)
        cursor.execute(update_query, recordTuple)
        print(cursor.rowcount, " create entry date updated successfully ")
        count = cursor.rowcount
        msg = f"""{count} source's last_update modified successfully"""
        debug_log('info', msg)
    except Exception as e:
        msg = 'Failed in update_source(): ' + str(e)
        debug_log('error', msg)


""" Adding category """ # to be deleted
def add_category(category_record):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO category (name, is_enabled) 
                                    VALUES (%s, %s) """

        recordTuple = (category_record['name'],category_record['is_enabled'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into category table")

    except mysql.connector.Error as error:
        msg = 'Failed in add_category(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into category table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            print("MySQL connection is closed")