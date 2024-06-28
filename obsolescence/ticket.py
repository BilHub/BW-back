import re
from database.connection import connect_to_db, close_connection
from datetime import datetime, timedelta


def create_ticket(data):
    connection = connect_to_db()
    cursor = connection.cursor(dictionary=True, buffered=True)
    current_time = datetime.now()
    six_months = timedelta(days=30 * 6)  # 6 months is roughly 180 days
    future_time = current_time + six_months
    for element in data:
        date_obj = datetime.strptime(element['eol'], '%Y-%m-%d')
        if date_obj < future_time:
            select_query = """ select a.responsable from asset a
                                                            where a.id = %s """
            args = (element['asset_id'],)
            cursor.execute(select_query, args)
            record = cursor.fetchone()
            responsable = record['responsable']

            # check if the record already exists
            select_query = "SELECT * FROM notif_obsolescence WHERE obsolescence_id=%(id_obso)s"
            cursor.execute(select_query, element)
            existing_record = cursor.fetchone()

            if create_ticket:
                print("existing record in create_ticket ")

            if not existing_record:
                insert_query = """INSERT IGNORE INTO notif_obsolescence (obsolescence_id, user_id, date)
                                                                            VALUES (%(obsolescence_id)s, %(user_id)s, %(date)s) """

                dict_insert = {'obsolescence_id': element['id_obso'], 'user_id': responsable, 'date': element['eol']}
                cursor.execute(insert_query, dict_insert)
    connection.commit()
    cursor.close()
    close_connection(connection)