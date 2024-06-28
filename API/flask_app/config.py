""" Flask configurations: this module is used to define variables of configurations """
import os
#basedir = os.path.abspath(os.path.dirname(__file__))
import pytest


class Config_old(object):

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'

    # Authy API Key
    # Found at https://dashboard.authy.com under your application
    # AUTHY_API_KEY = '2tSEKMgia3YFWSzHLaZ8iU7YXMgC69ON' # PGV_Authy
    AUTHY_API_KEY = 'b47fwWO9h6h9E847BoehY03lja0B61qi' # Twilio_PGV_2FA
    # AUTHY_API_KEY = 'qnYsHG8PVRBwnIiD1DIgZJ4CDE1Kl4FO' # PGV_2FA3

    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'scout'
    MYSQL_PASSWORD = '2.PGV_db'
    MYSQL_DB = 'pgvdb_schema5'

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'mysql://'+MYSQL_USER+':'+MYSQL_PASSWORD+'@'+MYSQL_HOST+':3306/'+MYSQL_DB
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    runPath = os.path.dirname(os.path.realpath(__file__))
    UPLOAD_FOLDER = os.path.join(runPath, '../../database/files/')
    ALLOWED_EXTENSIONS = {'.csv', '.xls', '.xlsx', '.xlsm', '.xlsb', '.odf', '.ods', '.odt'}
