import mysql.connector
from database.connection import connect_to_db, close_connection
from database.asset import add_multi_asset
import time
from debug.debug import debug_log

class Client_group:
    def __init__(self, **client_grp_dict):
        self.id = client_grp_dict['id']
        self.name = client_grp_dict['name']
        self.alerts = client_grp_dict['alerts']
        self.type = client_grp_dict['type']
        self.pesonal = client_grp_dict['list_client_personal']


class user:
    def __init__(self, **cient_prl_dict):
        self.username = cient_prl_dict['username']
        self.password_hash = cient_prl_dict['password_hash']
        self.country_code = cient_prl_dict['country_code']
        self.phone = cient_prl_dict['phone']
        self.email = cient_prl_dict['email']
        self.group = cient_prl_dict['client_group']
        self.role = cient_prl_dict['role']
        self.status = cient_prl_dict['status']
        self.authy_id = cient_prl_dict['authy_id']
        self.authy_status = cient_prl_dict['authy_status']


""" Adding client """
def add_client(record):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO user (username, email, password_hash, country_code, phone, groupe, role, status, authy_id, authy_status) 
                                    VALUES (%s, %s,%s,%s, %s,%s,%s, %s, %s, %s) """

        recordTuple = (record['username'],record['email'],record['password_hash'],record['country_code'],record['phone'],record['groupe'],record['role'],record['status'],record['authy_id'],record['authy_status'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into user table")

    except mysql.connector.Error as error:
        msg = 'Failed in add_user(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into user table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)


""" Adding analyst (CERT user) """
def add_analyst(record):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO analyst (username, email, password_hash, country_code, phone, role, status, authy_id, authy_status) 
                                    VALUES (%s, %s,%s,%s, %s,%s,%s, %s, %s) """

        recordTuple = (record['username'],record['email'],record['password_hash'],record['country_code'],record['phone'],record['role'],record['status'],record['authy_id'],record['authy_status'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into user table")

    except mysql.connector.Error as error:
        msg = 'Failed in add_analyst(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into analyst table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)

""" Adding client_groupe (entreprise)"""
def add_client_group(record):
    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO client_group (name, alerts, type, subscription) 
                                    VALUES (%s, %s,%s, %s) """

        recordTuple = (record['name'],record['alerts'],record['type'],record['subscription'])
        cursor.execute(insert_query, recordTuple)
        connection.commit()
        print(cursor.rowcount," record inserted successfully into client_group table")

    except mysql.connector.Error as error:
        msg = 'Failed in add_client_group(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into client_group table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")


""" Add asset_usage (Link asset to client_cpe)"""
def add_asset_usage(record,cursor):
    try:
    #     connection = connect_to_db()
    #     cursor = connection.cursor()
        insert_query = """INSERT IGNORE INTO asset_usage (asset_id, cpe, status) 
                                        VALUES (%s, %s, %s) """

        recordTuple = (record['asset_id'], record['cpe'], record['status'])
        cursor.execute(insert_query, recordTuple)
        # connection.commit()
        # print(cursor.rowcount," record inserted successfully into asset_usage table")
    except mysql.connector.Error as error:
        msg = 'Failed in add_asset_usage(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into asset_usage table {}".format(error))
    #
    # finally:
    #     if (connection.is_connected()):
    #         cursor.close()
    #         colse_connection(connection)
    #         print("MySQL connection is closed")



""" get asset_usage id from the database """
def get_asset_usage(asset_id,cpe,cursor=None): # the argument connection should be initied before the call of the function
    id = None
    try:
        if not cursor:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select id from asset_usage where asset_id = %s and cpe = %s"
        arg = (asset_id,cpe)
        cursor.execute(select_Query, arg)
        record = cursor.fetchone()
        if record:
            id = record['id']
        # return id
    except mysql.connector.Error as error:
        msg = 'Failed in get_asset_usage(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get asset_usage id {}".format(error))
        # return None
    finally:
        return id # int or None


""" Add multiple records to asset_usage (Link asset to client)"""
def add_multi_asset_usage(records,connection=None):
    count = 0
    try:
        debug_log('debug', 'Start add_multi_asset_usage()')
        if not connection:
            connection = connect_to_db()
        else:
            connection = connect_to_db() # debug
            # print('connection is OK') # debug
        cursor = connection.cursor()
        recordTuple = []
        for i in records:
            recordTuple.append((i))
        insert_query = """INSERT  IGNORE INTO asset_usage (asset_id, cpe, status) 
                                        VALUES (%s, %s, %s) """

        cursor.executemany(insert_query, recordTuple) # records are already initied in the parent function (add_assets_to_client)
        connection.commit()
        count = int(cursor.rowcount)
        # print(cursor.rowcount," record inserted successfully into asset_usage table")
    except Exception as error:
        msg = 'Failed in add_multi_asset_usage(): ' + str(error)
        debug_log('error', msg)
        print("Failed to insert into asset_usage table {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            debug_log('debug', 'End add_multi_asset_usage()')
        return count


""" Associate cpes to client assets (add multi asset_usage)"""
def link_asset_client(usage_list,group_id, cpe_credits=None): # this function is used by the import_cpe function (nb_cpes : number of cpes autorised to be added for thr client )
    nb_assets = len(usage_list) # number of assets contained in the imorted file
    nb_cpes = 0 # number of products contained in the imorted file
    nb_assets_inserted = 0 # number of assets inserted in the DB
    inserted_cpes = 0 # number of products inserted in the DB
    duplicated_cpes = 0  # to compte how many duplicated cpes are not added to the DB (usefll to show errors in the process of importing assets)
    nb = {'nb_assets': nb_assets, 'assets':nb_assets_inserted, 'nb_cpes': nb_cpes, 'cpes': inserted_cpes, 'duplicated_cpes':duplicated_cpes, 'cpe_credits': cpe_credits} # cpe_credits : cpe credits remaining
    try:
        debug_log('debug', 'Start link_asset_client()')
        connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)
        # Getting the company id (cleint group)
        # select_Query = "select id from client_group where name = %s"
        # select_record = (group_name,)
        # # cve_cursor = connection.cursor()
        # cursor.execute(select_Query, select_record)
        # record = cursor.fetchone()
        # group_id = record[0]
        # print('Group id: ',group_id)
        # Build the list of records to insert
        assets = [] # assets to be added to the DB
        new_assets = [] # asset usages of the assets that not exists in the DB
        asset_usage_records = [] # asset_usages records to be added to the DB
        managers_list = []
        # print('lenght asset_list: ',len(asset_list))
        """ Adding new assets to the DB """
        for u in usage_list: # list elements {asset_ref: , cpes: {id_cpe1, id_cpe2, id_cpe3, ...}}
            asset_id = get_asset_id(asset_ref=u['asset_ref'],groupe_id=group_id)
            nb_cpes += len(u['cpes'])
            if asset_id : #  asset already exists in the DB
                for cpe in u['cpes']:
                    usage_id = get_asset_usage(asset_id,cpe,cursor)
                    if usage_id:
                        duplicated_cpes += 1
                    else:
                        if cpe_credits > 0:
                            asset_usage_records.append([asset_id,cpe,0])  # asset usage record: [asset_id,cpe,status]
                            cpe_credits -= 1
            else:
                print('u manager', u['manager'])
                managers_list.append(u['manager'])
                assets.append([u['asset_ref'], group_id, 0, 0, u['importance'], u['manager'], u['service'], u['responsable']])  # asset record: [asset_ref,group_id,status,modified,importance,manager,service]
                new_assets.append(u)

        if len(new_assets)>0: # there is new assets to add into asset table
            nb_assets_inserted = add_multi_asset(assets,connection)
            print(nb_assets_inserted, " record inserted successfully into asset table")
            for na in new_assets:  # list elements {asset_ref: , cpe_list: {id_cpe1, id_cpe2, id_cpe3, ...}}
                asset_id = get_asset_id(asset_ref=na['asset_ref'], groupe_id=group_id)
                for cpe in na['cpes']:
                    if cpe_credits > 0:
                        asset_usage_records.append([asset_id, cpe, 0])  # asset usage record: [asset_id,cpe,status]
                        cpe_credits -= 1
                        break
        """Associating CPEs with assets"""
        inserted_cpes = add_multi_asset_usage(asset_usage_records,connection)
        print(inserted_cpes, " record inserted successfully into asset_usage table")
        nb['cpes'] = inserted_cpes
        nb['nb_cpes'] = nb_cpes
        nb['assets'] = nb_assets_inserted
        nb['duplicated_cpes'] = duplicated_cpes
        nb['cpe_credits'] = cpe_credits
        nb['managers'] = managers_list
        print('ajout ', nb)

    except mysql.connector.Error as error:
        msg = 'Failed in link_asset_client(): ' + str(error)
        debug_log('error', msg)
        print("Failed to associate cpes with client assets {}".format(error))

    finally:
        debug_log('debug', 'End link_asset_client()')
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
            # print("MySQL connection is closed")
        return nb

""" Adding assets imported from a file to a client (parse the list of assets to database tuples)"""
def add_assets_to_client(assets,client_id,connection=None): # the argument connection should be initied before the call of the function
    try:
        debug_log('debug', 'Start add_assets_to_client()')
        # print('To be developed')
        if not connection:
            connection = connect_to_db()
            # print('connection established in add_assets_to_client!')
        manager_id = get_manager(client_id, connection) # this function is used . manager should be specified in the csv/excel file made by the client
        records = []
        for asset in assets:
            for cpe in asset['cpes']:
                record = [asset['asset_ref'],cpe,client_id,None,manager_id,None] # importance, nb_cpe and service are set to null temporarily. manager
                records.append(record)
        """ Adding the records to the DB"""
        nb_inserted = add_multi_asset_usage(records,connection)
    except Exception as error:
            msg = 'Failed in add_assets_to_client(): ' + str(error)
            debug_log('error', msg)
    finally:
        if connection:
            close_connection(connection)
        if nb_inserted:
            return nb_inserted
        else:
            return 0
        debug_log('debug','End add_assets_to_client()')


""" get client_group id from the database """
def get_client(name, connection=None): # the argument connection should be initied before the call of the function
    id = None
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select id from client_group where name = %s"
        arg = (name,)
        cursor.execute(select_Query, arg)
        record = cursor.fetchone()

        id = record['id']
    except mysql.connector.Error as error:
        msg = 'Failed in get_client(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get client_group {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
        return id # int


""" get manager id (client_id) of an asset : set temporarily to run the import parsers without manager column in the csv/excel file """
def get_manager(client_group_id, connection=None): # the argument connection should be initied before the call of the function
    id = None
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select id from user where groupe = %s and role in ('s_user','ad_user')"
        arg = (client_group_id,)
        cursor.execute(select_Query, arg)
        record = cursor.fetchone()

        id = record['id']
    except mysql.connector.Error as error:
        msg = 'Failed in get_manager(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get get_manager {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
        return id # int


""" get asset id (asset.id) of an asset : select the asset by the name """
def get_asset_id(asset_ref,groupe_id, connection=None): # the argument connection should be initied before the call of the function
    id = None
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select id from asset where groupe = %s and asset_ref = %s"
        arg = (groupe_id,asset_ref)
        cursor.execute(select_Query, arg)
        record = cursor.fetchone()
        if record:
            id = record['id']
    except mysql.connector.Error as error:
        msg = 'Failed in get_asset_id(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get get_asset_id {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
        return id # int

""" get All clients informations """
def get_clients_info():  # get all clients information (name, subscription info, nb users, nb assetst and nb products)
    try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            clients_list = []
            select_Query = "select cg.id, cg.name, s.id as subs_id, COALESCE(s.start_at,'') as start_at, COALESCE(s.expire_on,'') as expire_on, s.status, " \
                           " COALESCE(p.name,'') as plan, COALESCE(p.user_credits,'') as user_credits, COALESCE(p.cpe_credits,'') as cpe_credits " \
                           "from client_group cg "\
                           "left join subscription s on  cg.subscription = s.id " \
                           "left join subs_plan p on  s.type = p.id "
            cursor.execute(select_Query)
            groups = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            for g in groups:
                """ Get client users count """
                select_count_users = "SELECT COUNT(id) as nb_users FROM user where groupe = %s"
                group_arg = (g['id'],)
                cursor.execute(select_count_users,group_arg)
                count = cursor.fetchone()
                nb_users = count['nb_users']
                """ Get client assets count """
                select_count_assets = "SELECT COUNT(a.id) as nb_assets FROM asset a " \
                "left join service s on  a.service = s.id " \
                "left join user u on  s.manager = u.id " \
                "WHERE u.groupe = %s "
                cursor.execute(select_count_assets, group_arg)
                count = cursor.fetchone()
                nb_assets = count['nb_assets']
                """ Get client products count """
                select_count_products = "SELECT COUNT(a_u.id) as nb_products FROM asset_usage a_u " \
                "left join asset a on  a_u.asset_id = a.id " \
                "left join service s on  a.service = s.id " \
                "left join user u on  s.manager = u.id " \
                "WHERE u.groupe = %s "
                cursor.execute(select_count_products, group_arg)
                count = cursor.fetchone()
                nb_products = count['nb_products']

                client = {'groupe_name':g['name'], 'nb_users':nb_users, 'nb_assets':nb_assets, 'nb_products':nb_products,'subs_id': g['subs_id'],'subs_status': g['status'],
                          'subscription': g['plan'],'start_at': g['start_at'],'expire_on': g['expire_on'],'user_credits': g['user_credits'],'cpe_credits': g['cpe_credits'] }
                clients_list.append(client)
            # for c in clients_list:
            #     print(c)
    except Exception as error:
            msg = 'Failed in get_clients_info(): ' + str(error)
            debug_log('error', msg)
    finally:
            close_connection(connection)
            return clients_list


""" Get all clients id and name"""
def get_clients(connection=None): # the argument connection should be initied before the call of the function
    records = []
    try:
        if not connection:
            connection = connect_to_db()
        cursor = connection.cursor(dictionary=True, buffered=True)

        select_Query = "select id, name from client_group "
        cursor.execute(select_Query)
        records = cursor.fetchall()
    except mysql.connector.Error as error:
        msg = 'Failed in get_clients(): ' + str(error)
        debug_log('error', msg)
        print("Failed to get client_group {}".format(error))

    finally:
        if (connection.is_connected()):
            cursor.close()
            close_connection(connection)
        return records


""" get All analysts informations """
def get_analysts():  # get all analysts information
    try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            analysts_list = []
            select_Query = "select id, username, email, role, status, last_conn from analyst where role = 'cert_user' "
            cursor.execute(select_Query)
            analysts = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            for a in analysts:
                """ Get analyst ticket count """
                select_count_users = "SELECT COUNT(id) as nb_tickets FROM pre_ticket where analysed_by = %s and status in (0,1) "
                group_arg = (a['id'],)
                cursor.execute(select_count_users,group_arg)
                count = cursor.fetchone()
                nb_tickets = count['nb_tickets']
                analyst = {'id':a['id'],'username':a['username'], 'nb_tickets':nb_tickets, 'email': a['email'],'role': a['role'],'status': a['status'],'last_conn': a['last_conn']}
                analysts_list.append(analyst)
            # for c in clients_list:
            #     print(c)
    except Exception as error:
            msg = 'Failed in get_analysts(): ' + str(error)
            debug_log('error', msg)
    finally:
            close_connection(connection)
            return analysts_list