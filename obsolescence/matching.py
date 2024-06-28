import re

from database.connection import connect_to_db, close_connection
from obsolescence.ticket import create_ticket

def get_existing_data_db(connection=None):
    connection = connect_to_db()
    print('connection', connection)
    cursor = connection.cursor(dictionary=True, buffered=True)
    select_query = "select * from obsolescence "
    cursor.execute(select_query, )
    data = cursor.fetchall()
    #  print('data', data)
    liste_cpes = []
    liste_cpes_details = []
    for element in data:
        dict_cpes = {}

        try:

            if not element['version']:
                number = ""
            elif not any(char.isdigit() for char in element['version']):
                number = ""
            else:
                number_str = re.findall(r'\d+\.*\d*', element['version'])[0]

                # Convert the string to a float value
                number = float(number_str)

                print(f"Extracted number: {number}")

        except ValueError:
            number = ""
        select_query = """ select a_u.asset_id, a_u.cpe from   asset_usage a_u
                                            left join client_cpe cp on  a_u.cpe = cp.id_cpe
                                            where cp.name = %s and cp.version = %s"""
        args = (element['product_cpe'], number)
        cursor.execute(select_query, args)
        records = cursor.fetchall()
        if records:
            for i in records:
                dict_cpes = {}
                dict_cpes['id_cpe'] = i['cpe']
                dict_cpes['id_obso'] = element['id']
                liste_cpes.append(dict_cpes)
                dict_cpes['eol'] = element['eol']
                dict_cpes['asset_id'] = i['asset_id']
            print('liste_cpes', liste_cpes)
            insert_exists_into_db(liste_cpes)
            create_ticket(liste_cpes)


def insert_exists_into_db(liste_cpes):
    connection = connect_to_db()
    cursor = connection.cursor(dictionary=True, buffered=True)

    for i in liste_cpes:

        # check if the record already exists
        select_query = "SELECT * FROM obso_exist WHERE id_cpe=%(id_cpe)s and id_obso=%(id_obso)s"
        cursor.execute(select_query, i)
        existing_record = cursor.fetchone()

        if existing_record:
            print("existing record in insert_exists_into_db ")

        if not existing_record:
            insert_query = """INSERT IGNORE INTO obso_exist (id_cpe, id_obso)
                                                            VALUES (%(id_cpe)s, %(id_obso)s) """
            cursor.execute(insert_query, i)

    connection.commit()
    cursor.close()
    close_connection(connection)
