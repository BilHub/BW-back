import mysql.connector
from debug.debug import debug_log
from database.connection import connect_to_db
from database.cve import calculate_final_score
from database.client import get_analysts
from datetime import datetime
from jira import JIRA
from requests_toolbelt import user_agent


def add_ticket(record,connection=None):
    debug_log('debug','Start add_ticket')
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True,buffered=True)
        insert_query = """INSERT IGNORE INTO ticket (usage_id, cve, created_at, opened_at, closed_at, status, score, action, comment, manager) 
                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('aut_alert record: \n',record)
        recordTuple = (record['usage_id'],record['cve'],record['created_at'], record['closed_at']
                       ,record['status'],record['score'],record['action'], record['manager'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into ticket table")
    except mysql.connector.errors as error:
        msg = 'Failed in add_ticket(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End add_ticket')


""" Update the status of the ticket """
def update_ticket(id,status,cursor):
    debug_log('debug','Start update_ticket')
    try:
        # connection = connect_to_db()
        # cursor = connection.cursor()
        update_query = """UPDATE  ignore ticket SET  status = %s where id = %s"""
        # print('cve_record',record)
        recordTuple = (status,id )
        cursor.execute(update_query, recordTuple)
        print(cursor.rowcount, " ticket updated successfully ")
    except mysql.connector.errors as error:
        msg = 'Failed in update_ticket(): ' + str(error)
        debug_log('error',msg)
    finally:
        debug_log('debug','End update_ticket')



""" Adding multile records to ticket table """
def add_multi_tickets(records_list,connection):
    debug_log('debug','Start add_multi_ticket()')
    try:
        cursor = connection.cursor(dictionary=True, buffered=True)
        # print('\nAdding multi ticket ...')
        insert_query = """INSERT IGNORE INTO ticket (usage_id, cve, created_at, opened_at, closed_at, status, score, action, comment, manager, pre_ticket) 
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('vulnerable_asset_record',record)
        recordTuple = []
        for i in records_list:
            recordTuple.append((i))


        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into ticket table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_multi_ticket(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple tickets {}".format(error))
    finally:
        debug_log('debug','End add_multi_ticket()')

""" Adding multile records to pre_ticket table """
def add_multi_pre_tickets(records_list,connection):
    debug_log('debug','Start add_multi_ticket()')
    try:
        cursor = connection.cursor(dictionary=True, buffered=True)
        # print('\nAdding multi ticket ...')
        insert_query = """INSERT IGNORE INTO pre_ticket (usage_id, cve, created_at, opened_at, treated_at, status, score, recommendation, comment, analysed_by) 
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        # print('vulnerable_asset_record',record)
        recordTuple = []
        for i in records_list:
            recordTuple.append((i))
        # print('recordTuple: ',recordTuple)
        cursor.executemany(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into pre_ticket table")

    except mysql.connector.Error as error:
        msg = 'Failed in add_multi_pre_tickets(): ' + str(error)
        debug_log('error',msg)
        print("Failed to add multiple pre_tickets {}".format(error))
    finally:
        debug_log('debug','End add_multi_pre_tickets()')

""" Adding pre_tickets to the DB from tickets list built in the matchin process (match_client_vuln_assets)"""
def insert_tickets_from_list(connection,tickets_list): # tickets list: ['cve':'','list_usages':[id1,id2,...]]
    debug_log('debug', 'Start insert_tickets_from_list()')
    try:
        tickets_records = []
        tickets_records_2 = []
        now = datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")
        for ticket in tickets_list:
            for usage_id in ticket['usages_list']:
                score = calculate_final_score(connection,ticket['cve'],usage_id)
                analyst_id = dispatcher() # affecting the ticket to the analyst that has the less of tickets
                record_pre_ticket = [usage_id,ticket['cve'],created_at,None,None,0,score,None,None,analyst_id] # ticket record [usage_id,cv,created_at,opened_at,treated_at,status,score,action,comment,analysed_at]
                """ Get the manager id"""
                cursor = connection.cursor(dictionary=True, buffered=True)
                select_query = "select  a.manager " \
                               "FROM asset a " \
                               "left join asset_usage a_u on  a.id= a_u.asset_id " \
                               "where a_u.id =  %s "
                usage_arg = (usage_id,)  # (usage_id,cve_id)
                cursor.execute(select_query, usage_arg)
                manager_dict = cursor.fetchone()
                manager_id = int(manager_dict['manager'])
                record_ticket = [usage_id, ticket['cve'], created_at, None, None, 0, score, None, None, manager_id, None]
                # tickets_records.append(record_pre_ticket)
                tickets_records.append(record_ticket)
        # add_multi_pre_tickets(tickets_records,connection)
        add_multi_tickets(tickets_records,connection)

    except mysql.connector.Error as error:
        msg = 'Failed in insert_tickets_from_list(): ' + str(error)
        debug_log('error', msg)
        print("Failed to add multiple tickets {}".format(error))
    finally:
        debug_log('debug', 'End insert_tickets_from_list()')

""" getting the analyst id that has the less of tickets"""
def dispatcher():
    min_ticket = 0
    analyst_id = None
    try:
        analysts = get_analysts()
        for a in analysts: # {'id':a['id'],'username':a['username'], 'nb_tickets':nb_tickets ... }
            if a['nb_tickets'] <= min_ticket:
                min_ticket = a['nb_tickets']
                analyst_id = a['id']
    except mysql.connector.Error as error:
        msg = 'Failed in dispatcher(): ' + str(error)
        debug_log('error', msg)
        print("Failed in dispatcher {}".format(error))
    finally:
        return analyst_id