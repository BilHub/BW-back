import flask
from flask import request, jsonify
from database.connection import connect_to_db, close_connection # predefined functions to onpen/close connection to DB
import re

app = flask.Flask(__name__)
app.config["DEBUG"] = True

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


@app.route('/', methods=['GET'])
def home():
    return '''<h1>Distant Reading Archive</h1>
<p>A prototype API for distant reading of science fiction novels.</p>'''


""" Getting all cpes from the DB """
@app.route('/api/v1/resources/cpes/all', methods=['GET'])
def api_all():
    connection = connect_to_db()
    cursor = connection.cursor(dictionary=True)

    select_Query = """ select * from client_asset """
    cursor.execute(select_Query)

    records = cursor.fetchall()

    return jsonify(records)


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


""" Filetering cpes from the DB"""
@app.route('/api/v1/resources/cpes', methods=['GET'])
def api_filter():
    query_parameters = request.args

    producer = query_parameters.get('producer')
    name = query_parameters.get('name')
    version = query_parameters.get('version')
    print('producer: ',producer,'name: ',name,'version: ',version)
    args_list = []
    # select_Query = """ select * from client_asset WHERE producer = %s AND name = %s AND version = %s"""
    select_Query = """ select * from client_asset WHERE """

    if producer:
        select_Query += ' producer=%s AND'
        args_list.append(producer)
    if name:
        select_Query += ' name=%s AND'
        args_list.append(name)
    if version:
        select_Query += ' version=%s AND'
        args_list.append(version)
    if not (producer or name or version):
        return page_not_found(404)


    # query_args = (producer,name,version)
    final_query = re.sub('AND$','',select_Query) # remove "AND" string from the end of the query
    query_args = tuple(args_list)

    connection = connect_to_db()
    cursor = connection.cursor(dictionary=True)
    cursor.execute(final_query,query_args)
    results = cursor.fetchall()
    # print(results)
    close_connection(connection)
    return jsonify(results)



app.run()