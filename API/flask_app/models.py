""" This module contains SqlAlchemy models (classes) of the different entities (table or objects) of the platform and the functions used by every model"""

from API.flask_app.app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from API.authy.utils import authy_user_has_app, send_authy_one_touch_request
from database.connection import connect_to_db, close_connection
from database.client import link_asset_client, delete_cpes
from parsers.uni_parser import parse_all
from debug.debug import debug_log, debug_new_line
from datetime import datetime
from functools import wraps
from flask_login import current_user
from sqlalchemy import event
from flask_sqlalchemy import SQLAlchemy

from jira import JIRA
from requests_toolbelt import user_agent

""" Classes/Models """


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    AUTHY_STATUSES = ('unverified', 'onetouch', 'sms', 'token', 'approved', 'denied')
    ROLES = ('s_user', 'ad_user', 'cert_ad', 'cert_user')

    id = db.Column(db.Integer, primary_key=True)
    username: object = db.Column(db.String(64), index=True, unique=True, nullable=False)
    nom = db.Column(db.String(45))
    prenom = db.Column(db.String(45))
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # full_name = db.Column(db.String(256))
    country_code = db.Column(db.Integer)
    phone = db.Column(db.String(16), unique=True)
    groupe = db.Column(db.Integer, db.ForeignKey('client_group.id'), nullable=False)
    # company is the groupe object  (backref from Client_group.users)
    role = db.Column(db.Enum(*ROLES, name='roles'))
    status = db.Column(db.Integer)
    authy_id = db.Column(db.Integer)
    authy_status = db.Column(db.Enum(*AUTHY_STATUSES, name='authy_statuses'))
    last_conn = db.Column(db.DateTime, default=datetime.utcnow())
    services = db.relationship('Service', backref='user_manager', lazy='dynamic')
    assets = db.relationship('Asset', backref='user_manager', lazy='dynamic')
    alerts = db.relationship('Aut_alert', backref='user_responsable', lazy='dynamic')
    secret_2fa = db.Column(db.String(45))
    first_login = db.Column(db.Boolean, default=False)

    # def __init__(self,email,password,username,country_code,phone,authy_id,authy_status='approved',):
    def __init__(self, email, username, nom, prenom, country_code, phone, groupe, status, authy_id=None,
                 authy_status='approved', role='s_user'):
        self.email = email
        self.username = username
        self.nom = nom
        self.prenom = prenom
        self.country_code = country_code
        self.phone = phone
        self.authy_id = authy_id
        self.authy_status = authy_status
        self.groupe = groupe
        self.role = role
        self.status = status
        # self.set_password(password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):  # generate a password for the user
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_assets(self):  # get all assets and their CPEs managed by the user (to be modified)
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select a.id, a.asset_ref, a.status, cc.id_cpe, cc.producer, cc.name , cc.version " \
                           "from asset a " \
                           "left join asset_usage au on au.asset_id = a.id " \
                           "left join client_cpe cc on cc.id_cpe = au.cpe " \
                           "left join service s on  a.service = s.id " \
                           "where  a.groupe = %s and a.responsable = %s"  # manager should be linked via the service
            arg = (self.groupe, self.id)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            return records
        except Exception as error:
            msg = 'Failed in User.get_assets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_assets_ref(self):  # get all assets names managed by the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select a.id, a.asset_ref  " \
                           "from asset a " \
                           "left join service s on  a.service = s.id " \
                           "where  a.groupe = %s and s.manager = %s"

            arg = (self.groupe, self.id)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')

            return records
        except Exception as error:
            msg = 'Failed in User.get_assets_ref(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_client_assets(self, asset_ref=None, manager=None, service=None, status=None,
                          sort_by='asset_ref'):  # get all assets of the client with filter
        records = []
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            if self.role == 'ad_user':
                select_Query = "select asset.id, asset_ref, asset.status, au.cpe, cc.producer, cc.name , cc.version,  COALESCE(importance,'') as importance, COALESCE(service.name,'') as service, COALESCE(user.username,'') as manager " \
                               "from asset " \
                               "left join asset_usage au on au.asset_id = asset.id " \
                               "left join client_cpe cc on cc.id_cpe = au.cpe " \
                               "left join service on  asset.service = service.id " \
                               "left join user on  service.manager = user.id " \
                               "where asset.groupe = %s"

                list_args = [self.groupe]
                """ Adding the filters to the query """
                if asset_ref:
                    asset_filter = ' AND asset_ref = %s'
                    select_Query += asset_filter
                    list_args.append(asset_ref)
                if manager:
                    manager_filter = ' AND user.username = %s'
                    select_Query += manager_filter
                    list_args.append(manager)
                if service:
                    service_filter = ' AND service.name = %s'
                    select_Query += service_filter
                    list_args.append(service)
                if status and status != 'None':
                    status_filter = ' AND asset.status = %s'
                    select_Query += status_filter
                    list_args.append(int(status))
                """ add the sort argument to the query """
                select_Query += f""" order by {sort_by} """
                arg = tuple(list_args)
                cursor.execute(select_Query, arg)
                records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
        except Exception as error:
            msg = 'Failed in User.get_client_assets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            if connection:
                close_connection(connection)
            return records  # returned list: {'id': 918, 'asset_ref': 'BRL008', 'manager': 'user1', 'service': None, 'importance': None}

    def get_tickets(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read, t.responsable as res, " \
                           " t.score, t.status, a.asset_ref, t.comment, t.action,  a_u.cpe, c.description, s.name " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where s.manager = %s and t.status <> -1 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_user_tickets(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref, t.comment, t.action,  a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where t.responsable = %s and t.status <> -1 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_closed_tickets(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref, t.comment, t.action, a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where s.manager = %s and t.status = -1 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_closed_tickets_team(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref, t.comment, t.action, a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where t.responsable = %s and t.status = -1 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_all_tickets(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref,  a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where s.manager = %s  order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_unread_tickets(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref,  a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where s.manager = %s and t.status <> -1 and t.read=0 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_unread_tickets_team(self):  # get all tickets assigned to the user
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read," \
                           " t.score, t.status, a.asset_ref,  a_u.cpe, c.description " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where t.responsable = %s and t.status <> -1 and t.read=0 order by created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in User.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    """ Get all users tickets"""

    def get_all_tickets(self, cve=None, manager=None, score=None, status=None, opened_at_sup=None, opened_at_inf=None,
                        closed_at_sup=None, closed_at_inf=None, sort_by='created_at',
                        direction='ASC'):  # get all tickets assigned to the user
        records = []
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            if self.role == 'ad_user':
                select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at," \
                               "t.score, t.status, u.username as manager " \
                               "FROM ticket t " \
                               "left join asset_usage a_u on  t.usage_id = a_u.id " \
                               "left join asset a on  a_u.asset_id = a.id " \
                               "left join service s on  a.service = s.id " \
                               "left join user u on  s.manager = u.id " \
                               "where u.groupe = %s  "
                list_args = [self.groupe]
                """ Adding the filters to the query """
                if cve:
                    cve_filter = ' AND t.cve = %s'
                    select_Query += cve_filter
                    list_args.append(cve)
                if manager and manager != 'None':
                    manager_filter = ' AND u.id = %s'
                    select_Query += manager_filter
                    list_args.append(manager)
                if score and score != 'None':
                    score_filter = ' AND t.score > %s'
                    select_Query += score_filter
                    list_args.append(score)
                if status and status != 'None':
                    status_filter = ' AND t.status = %s'
                    select_Query += status_filter
                    list_args.append(int(status))
                if opened_at_sup and opened_at_sup != 'None':
                    opened_at_sup_filter = ' AND t.opened_at > %s'
                    select_Query += opened_at_sup_filter
                    list_args.append(opened_at_sup)
                if opened_at_inf and opened_at_inf != 'None':
                    opened_at_inf_filter = ' AND t.opened_at < %s'
                    select_Query += opened_at_inf_filter
                    list_args.append(opened_at_inf)
                if closed_at_sup and closed_at_sup != 'None':
                    closed_at_sup_filter = ' AND t.closed_at > %s'
                    select_Query += closed_at_sup_filter
                    list_args.append(closed_at_sup)
                if closed_at_inf and closed_at_inf != 'None':
                    closed_at_inf_filter = ' AND t.closed_at < %s'
                    select_Query += closed_at_inf_filter
                    list_args.append(closed_at_inf)
                """ add the sort argument to the query """
                select_Query += f""" order by {sort_by} {direction} """
                arg = tuple(list_args)
                cursor.execute(select_Query, arg)
                records = cursor.fetchall()
                if records:
                    print('\n', len(records), ' tickets trouvés')
        except Exception as error:
            msg = 'Failed in User.get_all_tickets(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return records

    """ Get only the user tickets"""

    def get_own_tickets(self, cve=None, manager=None, score=None, status=None, opened_at_sup=None, opened_at_inf=None,
                        closed_at_sup=None, closed_at_inf=None, sort_by='created_at',
                        direction='ASC'):  # get all tickets assigned to the user
        records = []
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            if self.role == 's_user':
                select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at," \
                               "t.score, t.status, u.username as manager " \
                               "FROM ticket t " \
                               "left join asset_usage a_u on  t.usage_id = a_u.id " \
                               "left join asset a on  a_u.asset_id = a.id " \
                               "left join service s on  a.service = s.id " \
                               "left join user u on  s.manager = u.id " \
                               "where u.groupe = %s and u.id = %s "
                list_args = [self.groupe, self.id]
                """ Adding the filters to the query """
                if cve:
                    cve_filter = ' AND t.cve = %s'
                    select_Query += cve_filter
                    list_args.append(cve)
                if manager and manager != 'None':
                    manager_filter = ' AND u.id = %s'
                    select_Query += manager_filter
                    list_args.append(manager)
                if score and score != 'None':
                    score_filter = ' AND t.score > %s'
                    select_Query += score_filter
                    list_args.append(score)
                if status and status != 'None':
                    status_filter = ' AND t.status = %s'
                    select_Query += status_filter
                    list_args.append(int(status))
                if opened_at_sup and opened_at_sup != 'None':
                    opened_at_sup_filter = ' AND t.opened_at > %s'
                    select_Query += opened_at_sup_filter
                    list_args.append(opened_at_sup)
                if opened_at_inf and opened_at_inf != 'None':
                    opened_at_inf_filter = ' AND t.opened_at < %s'
                    select_Query += opened_at_inf_filter
                    list_args.append(opened_at_inf)
                if closed_at_sup and closed_at_sup != 'None':
                    closed_at_sup_filter = ' AND t.closed_at > %s'
                    select_Query += closed_at_sup_filter
                    list_args.append(closed_at_sup)
                if closed_at_inf and closed_at_inf != 'None':
                    closed_at_inf_filter = ' AND t.closed_at < %s'
                    select_Query += closed_at_inf_filter
                    list_args.append(closed_at_inf)
                """ add the sort argument to the query """
                select_Query += f""" order by {sort_by} {direction} """
                arg = tuple(list_args)
                cursor.execute(select_Query, arg)
                records = cursor.fetchall()
                if records:
                    print('\n', len(records), ' tickets trouvés')
        except Exception as error:
            msg = 'Failed in User.get_all_tickets(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return records

    @property
    def has_authy_app(self):
        return authy_user_has_app(self.authy_id)

    def send_one_touch_request(self):
        return send_authy_one_touch_request(self.authy_id, self.email)

    @property
    def rolenames(self):
        try:
            return self.role.split(',')
        except Exception:
            return []

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    @property
    def identity(self):
        return self.id

    def is_valid(self):
        return self.status


class Analyst(UserMixin, db.Model):
    __tablename__ = 'analyst'

    AUTHY_STATUSES = ('unverified', 'onetouch', 'sms', 'token', 'approved', 'denied')
    ROLES = ('cert_ad', 'cert_user')

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    country_code = db.Column(db.Integer)
    phone = db.Column(db.String(16), unique=True)
    role = db.Column(db.Enum(*ROLES, name='roles'))
    status = db.Column(db.Integer)
    authy_id = db.Column(db.Integer)
    authy_status = db.Column(db.Enum(*AUTHY_STATUSES, name='authy_statuses'))
    last_conn = db.Column(db.DateTime, default=datetime.utcnow())
    pre_tickets = db.relationship('Pre_ticket', backref='analyst')
    reset_token = db.Column(db.String(100), unique=True)

    # def __init__(self,email,password,username,country_code,phone,authy_id,authy_status='approved',):
    def __init__(self, email, username, country_code, phone, status, authy_id=None, authy_status='approved',
                 role='s_user'):
        self.email = email
        self.username = username
        self.country_code = country_code
        self.phone = phone
        self.authy_id = authy_id
        self.authy_status = authy_status
        self.role = role
        self.status = status
        # self.set_password(password)

    def __repr__(self):
        return '<Analyst {}>'.format(self.username)

    def set_password(self, password):  # generate a password for the user
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_tickets_cert(self):
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "SELECT t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.read, t.responsable as res, t.score, t.status, a.asset_ref, t.comment, t.action, a_u.cpe, c.description, s.name " \
                           "FROM ticket t " \
                           "LEFT JOIN asset_usage a_u ON t.usage_id = a_u.id " \
                           "LEFT JOIN asset a ON a_u.asset_id = a.id " \
                           "LEFT JOIN service s ON a.service = s.id " \
                           "LEFT JOIN cve_temp c ON t.cve = c.id " \
                           "WHERE s.manager = %s AND t.status <> -1 AND t.status IS NOT NULL " \
                           "ORDER BY created_at"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            return records
        except Exception as error:
            msg = 'Failed in Analyst.get_tickets_cert(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_tickets(self):  # get all tickets assigned to the analyst
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.treated_at,'') as treated_at, COALESCE(t.created_at,'') as created_at," \
                           " t.score, t.status, a.asset_ref, cg.name as groupe,  a_u.cpe, c.description " \
                           "FROM pre_ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join client_group cg on  cg.id = a.groupe " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where t.analysed_by = %s and t.status NOT IN (2,3) order by created_at"  # pre ticket has not been treated yet (status != 2 or 3)
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' cpe trouvés')
            return records
        except Exception as error:
            msg = 'Failed in Analyst.get_tickets(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    """ Getting all analysts tickets without or with filters (for the CERT admin)"""

    def get_all_tickets(self, cve=None, analyst=None, score=None, status=None, opened_at_sup=None, opened_at_inf=None,
                        treated_at_sup=None, treated_at_inf=None, sort_by='created_at',
                        direction='ASC'):  # get all tickets assigned to the user
        records = []
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            if self.role == 'cert_ad':
                select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.treated_at,'') as treated_at, COALESCE(t.created_at,'') as created_at," \
                               "t.score, t.status, a.username as manager " \
                               "FROM pre_ticket t " \
                               "left join asset_usage a_u on  t.usage_id = a_u.id " \
                               "left join asset a on  a_u.asset_id = a.id " \
                               "left join analyst a on  t.analysed_by = a.id "
                list_args = []
                """ Adding the filters to the query """
                if cve:
                    cve_filter = ' AND t.cve = %s'
                    select_Query += cve_filter
                    list_args.append(cve)
                if analyst and analyst != 'None':
                    manager_filter = ' AND a.id = %s'
                    select_Query += manager_filter
                    list_args.append(analyst)
                if score and score != 'None':
                    score_filter = ' AND t.score > %s'
                    select_Query += score_filter
                    list_args.append(score)
                if status and status != 'None':
                    status_filter = ' AND t.status = %s'
                    select_Query += status_filter
                    list_args.append(int(status))
                if opened_at_sup and opened_at_sup != 'None':
                    opened_at_sup_filter = ' AND t.opened_at > %s'
                    select_Query += opened_at_sup_filter
                    list_args.append(opened_at_sup)
                if opened_at_inf and opened_at_inf != 'None':
                    opened_at_inf_filter = ' AND t.opened_at < %s'
                    select_Query += opened_at_inf_filter
                    list_args.append(opened_at_inf)
                if treated_at_sup and treated_at_sup != 'None':
                    treated_at_sup_filter = ' AND t.treated_at > %s'
                    select_Query += treated_at_sup_filter
                    list_args.append(treated_at_sup)
                if treated_at_inf and treated_at_inf != 'None':
                    treated_at_inf_filter = ' AND t.treated_at < %s'
                    select_Query += treated_at_inf_filter
                    list_args.append(treated_at_inf)
                """ add the sort argument to the query """
                select_Query += f""" order by {sort_by} {direction} """
                arg = tuple(list_args)
                cursor.execute(select_Query, arg)
                records = cursor.fetchall()
                if records:
                    print('\n', len(records), ' tickets trouvés')
        except Exception as error:
            msg = 'Failed in Analyst.get_all_tickets(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return records

    @property
    def has_authy_app(self):
        return authy_user_has_app(self.authy_id)

    def send_one_touch_request(self):
        return send_authy_one_touch_request(self.authy_id, self.email)


class password_reset_cert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey('analyst.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(255))
    expiration_date = db.Column(db.DateTime, default=datetime.utcnow)


class Client_group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    alerts = db.Column(db.Integer)
    type = db.Column(db.String(128))
    subscription = db.Column(db.Integer, db.ForeignKey('subscription.id', ondelete='SET NULL'))
    # subs_obj is the Subscription object of the subscription (backref from Subscription.client)
    users = db.relationship('User', backref='company',
                            lazy='dynamic')  # company is the client_group argument that should be specified in the creation of the user object
    assets = db.relationship('Asset', backref='owner', lazy='dynamic')

    # usages = db.relationship('Asset_usage', backref='client')

    def update_products(self, cpes_to_delete, actif):
        try:
            delete_cpes(cpes_to_delete, self.id, actif)
        except Exception as error:
            msg = 'Failed in client_groupe.delete_cpes(): ' + str(error)
            debug_log('error', msg)
            print("Failed to delete cpes {}".format(error))

    def import_assets(self, import_file_path, cpe_credits):
        results = 0
        try:
            assets = parse_all(import_file_path, self.name)
            if assets:
                results = link_asset_client(assets, self.id, cpe_credits)
                msg = f""" {results['cpes']} of client products added succefully to the DB!"""
                debug_log('info', msg)
        except Exception as error:
            msg = 'Failed in client_groupe.import_assets(): ' + str(error)
            debug_log('error', msg)
            print("Failed to import client assets {}".format(error))

        finally:
            # debug_log('debug', 'End client_groupe.import_assets()')
            return results

    def get_services(self):  # get all client services
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select service.id, service.name, service.responsable, service.localisation, service.description,  COALESCE(username,'') as manager from service, user  where groupe = %s AND service.manager = user.id"
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchall()
            # print('\n', len(records), ' services trouvés')

            return records
        except Exception as error:
            msg = 'Failed in Client_group.get_services(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    """ get All clients informations """

    def get_all_info(
            self):  # get all informations of the client (name, subscription info, nb users, nb assetst, nb products and subscription information)
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            client_info = None
            select_Query = "select COALESCE(s.start_at,'') as start_at, COALESCE(s.expire_on,'') as expire_on, " \
                           " COALESCE(p.name,'') as plan, COALESCE(p.user_credits,'') as user_credits, COALESCE(p.cpe_credits,'') as cpe_credits " \
                           " from client_group cg " \
                           " left join subscription s on  cg.subscription = s.id " \
                           " left join subs_plan p on  s.type = p.id " \
                           " Where cg.id = %s "
            query_arg = (self.id,)
            cursor.execute(select_Query, query_arg)
            group = cursor.fetchone()
            # print('\nclient information: ', group')

            """ Get client users count """
            select_count_users = "SELECT COUNT(id) as nb_users FROM user where groupe = %s"
            group_arg = (self.id,)
            cursor.execute(select_count_users, group_arg)
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

            client_info = {'groupe_name': self.name, 'type': self.type, 'alerts': self.alerts, 'nb_users': nb_users,
                           'nb_assets': nb_assets,
                           'nb_products': nb_products,
                           'subscription': group['plan'], 'start_at': group['start_at'],
                           'expire_on': group['expire_on'],
                           'user_credits': group['user_credits'], 'cpe_credits': group['cpe_credits']}

            # for c in clients_list:
            #     print(c)
        except Exception as error:
            msg = 'Failed in lient_group.get_all_info(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return client_info

    def get_product_credits(self):  # get product count of the client and user credits from client subscription
        nb_products = None
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            """ Get client products count """
            select_count_products = "SELECT COUNT(a_u.id) as nb_products FROM asset_usage a_u " \
                                    "left join asset a on  a_u.asset_id = a.id " \
                                    "left join service s on  a.service = s.id " \
                                    "left join user u on  s.manager = u.id " \
                                    "WHERE u.groupe = %s "
            group_arg = (self.id,)
            cursor.execute(select_count_products, group_arg)
            record = cursor.fetchone()
            nb_products = record['nb_products']
        except Exception as error:
            msg = 'Failed in client_group.get_product_credits(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return nb_products

    def get_users_info(
            self):  # get informations about client users (username, status, managed services, , nassets count, tickets count)
        list_users = []
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            select_Query = "select id, username, status, email, last_conn from user where role = 's_user' and groupe = %s "
            query_arg = (self.id,)
            cursor.execute(select_Query, query_arg)
            users = cursor.fetchall()
            # print('\nuser information: ', group')

            """ Get services managed by each user """
            for u in users:
                select_count_users = "SELECT name  FROM service where manager = %s"
                manager_arg = (u['id'],)
                cursor.execute(select_count_users, manager_arg)
                service_records = cursor.fetchall()
                services = [s['name'] for s in service_records]
                """ Get user assets count """
                select_count_assets = "SELECT COUNT(a.id) as nb_assets FROM asset a " \
                                      "left join service s on  a.service = s.id " \
                                      "WHERE s.manager = %s "
                cursor.execute(select_count_assets, manager_arg)
                count = cursor.fetchone()
                nb_assets = count['nb_assets']
                """ Get client tickets count """
                select_count_products = "SELECT COUNT(t.id) as nb_tickets FROM ticket t " \
                                        "left join asset_usage a_u on  t.usage_id = a_u.id " \
                                        "left join asset a on  a_u.asset_id = a.id " \
                                        "left join service s on  a.service = s.id " \
                                        "WHERE s.manager = %s and t.status <> -1 "
                cursor.execute(select_count_products, manager_arg)
                count = cursor.fetchone()
                nb_tickets = count['nb_tickets']

                user_info = {'username': u['username'], 'email': u['username'], 'status': u['status'],
                             'last_conn': u['last_conn'], 'services': services, 'nb_assets': nb_assets,
                             'nb_tickets': nb_tickets}
                list_users.append(user_info)

            # for c in clients_list:
            #     print(c)
        except Exception as error:
            msg = 'Failed in client_group.get_users_info(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return list_users

    """ get subscription informations """

    def get_subscription_info(
            self):  # get subscription information (subscription info, nb users, nb assetst and nb products)
        client_info = None
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)
            select_Query = "select  s.id as subs_id, COALESCE(s.start_at,'') as start_at, COALESCE(s.expire_on,'') as expire_on, s.status, " \
                           " COALESCE(p.name,'') as plan, COALESCE(p.user_credits,'') as user_credits, COALESCE(p.cpe_credits,'') as cpe_credits " \
                           "from subscription s " \
                           "left join client_group cg on cg.subscription = s.id " \
                           "left join subs_plan p on  s.type = p.id " \
                           "where cg.id = %s "
            group_arg = (self.id,)
            cursor.execute(select_Query, group_arg)
            subs_info = cursor.fetchone()
            """ Get client users count """
            select_count_users = "SELECT COUNT(id) as nb_users FROM user where groupe = %s"
            cursor.execute(select_count_users, group_arg)
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

            client_info = {'nb_users': nb_users, 'nb_assets': nb_assets,
                           'nb_products': nb_products, 'subs_id': subs_info['subs_id'],
                           'subs_status': subs_info['status'],
                           'subscription': subs_info['plan'], 'start_at': subs_info['start_at'],
                           'expire_on': subs_info['expire_on'],
                           'user_credits': subs_info['user_credits'], 'cpe_credits': subs_info['cpe_credits']}
            # for c in clients_list:
            #     print(c)
        except Exception as error:
            msg = 'Failed in get_subscription_info(): ' + str(error)
            debug_log('error', msg)
        finally:
            close_connection(connection)
            return client_info

    def __repr__(self):
        return '<Client {}>'.format(self.name)


class Client_cpe(db.Model):
    id_cpe = db.Column(db.String(256), primary_key=True)
    type = db.Column(db.String(4), nullable=False)
    producer = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    version = db.Column(db.String(32))
    assets = db.relationship('Asset_usage', backref='cpes_usage')

    # """ This function remove spaces and convert to lower case th product name or vendor"""
    # @property
    # def normalise_cpe_name(name):
    #     cpe_name = name
    #     try:
    #         cpe_format = name.strip()
    #         cpe_name = cpe_format.replace(' ', '_')
    #         cpe_name = cpe_name.lower()
    #     except Exception as error:
    #         msg = 'Failed in normalize_cpe_name: ' + str(error)
    #         debug_log('error', msg)
    #         # print("Failed to insert into cpe table {}".format(error))
    #     finally:
    #         return cpe_name

    def set_cpe(self, type, producer, name, version='*'):
        cpe23 = 'cpe:2.3:'
        suffix = ':*:*:*:*:*:*:*'
        cpe_id = cpe23 + type + ':' + producer + ':' + name + ':' + version + suffix
        self.id_cpe = cpe_id
        self.type = type
        self.producer = producer
        self.name = name
        self.version = version

    def get_full_product_name(self):
        product = ''
        try:
            producer = self.producer.replace('_', ' ')
            name = self.name.replace('_', ' ')
            if self.version == '*':
                version = ''
            else:
                version = self.version
            product = producer.title() + ' ' + name.title() + ' ' + version
        except Exception as error:
            msg = 'Failed in asset.get_full_product_name: ' + str(error)
            debug_log('error', msg)
            # print("Failed to insert into cpe table {}".format(error))
        finally:
            return product

    def __repr__(self):
        return '<Client_cpe {}>'.format(self.id_cpe)


class Asset(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    groupe = db.Column(db.Integer(), db.ForeignKey('client_group.id', ondelete='CASCADE'))
    # owner is the groupe object (backref from Client_group.assets)
    asset_ref = db.Column(db.String(32), nullable=False)
    status = db.Column(db.Integer(), default=0)
    modified = db.Column(db.Integer(), default=0)
    importance = db.Column(db.Integer())
    service = db.Column(db.Integer, db.ForeignKey('service.id'))
    # service_obj is the Service object (backref from Service.assets)
    manager = db.Column(db.Integer, db.ForeignKey(
        'user.id'))  # the asset manager is the service manager (this column is added in case the are changes in the conception)
    cpes = db.relationship('Asset_usage', backref='assets_usage', cascade="all, delete")
    responsable = db.Column(db.Integer())

    def __repr__(self):
        return '<Asset {}>'.format(self.id)


class Service(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(128), nullable=False)

    manager = db.Column(db.Integer, db.ForeignKey('user.id'))
    localisation = db.Column(db.String(56), nullable=True)
    description = db.Column(db.String(256), nullable=True)
    responsable = db.Column(db.String(256), nullable=True)
    # user_manager is the user object of the manager (backref from User.services)
    assets = db.relationship('Asset', backref='service_obj', lazy='dynamic')

    def get_assets_count(self):  # get all client services
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select count(*) as assets_count from asset  where service = %s "
            arg = (self.id,)
            cursor.execute(select_Query, arg)
            records = cursor.fetchone()
            # print(f'''Nombre d'actifs pour le service {self.name}: records['assets_count'])

            return records['assets_count']
        except Exception as error:
            msg = 'Failed in Client_group.get_services(): ' + str(error)
            debug_log('error', msg)
            return None
        finally:
            close_connection(connection)

    def __repr__(self):
        return '<Service {}>'.format(self.id)


class Asset_usage(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    cpe = db.Column(db.String(256), db.ForeignKey('client_cpe.id_cpe', ondelete='CASCADE'))
    # cpes_usage is the client_cpe object of the cpe (backref from Client_cpe.assets)
    asset_id = db.Column(db.Integer(), db.ForeignKey('asset.id', ondelete='CASCADE'))
    # assets_usage is the asset object of the asset_id (backref from Asset.cpes)
    status = db.Column(db.Integer(), default=0)
    tickets = db.relationship('Ticket', backref='usage', lazy='dynamic')
    pre_tickets = db.relationship('Pre_ticket', backref='usage', lazy='dynamic')

    def __repr__(self):
        return '<Asset_usage {}>'.format(self.id)


class Cve_temp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    links = db.Column(db.Text)
    published_at = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    cvss2 = db.Column(db.Float)
    cvss3 = db.Column(db.Float)
    mitigations = db.Column(db.String(128))
    workarounds = db.Column(db.String(128))
    tickets = db.relationship('Ticket', backref='cve_obj', lazy='dynamic')
    pre_tickets = db.relationship('Pre_ticket', backref='cve_obj', lazy='dynamic')

    def __repr__(self):
        return '<Cve_temp {}>'.format(self.id)


class Ticket(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    usage_id = db.Column(db.Integer, db.ForeignKey('asset_usage.id', ondelete='CASCADE'))
    # usage is the asset_usage object of the usage_id column (backref from Asset_usage.tickets)
    cve = db.Column(db.Integer(), db.ForeignKey('cve_temp.id', ondelete='RESTRICT'))
    # cve_obj is the cve_temp object of the cve column (backref from Cve_temp.tickets)
    created_at = db.Column(db.DateTime, nullable=False)
    opened_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    status = db.Column(db.Integer(), default=0)
    score = db.Column(db.Float)
    action = db.Column(db.String(64))
    comment = db.Column(db.String(512))
    manager = db.Column(db.Integer, db.ForeignKey('user.id'))
    pre_ticket = db.Column(db.Integer, db.ForeignKey('pre_ticket.id'))
    read = db.Column(db.Integer(), default=0)
    info = db.Column(db.String(256))
    due_date = db.Column(db.DateTime)
    responsable = db.Column(db.Integer, db.ForeignKey('user.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'status': self.status,
            'due_date': self.due_date,
            'info': self.info,
            'read': self.read,
            'responsable': self.responsable,
            'created_at': self.created_at,
            'opened_at': self.opened_at,
            'closed_at': self.closed_at,
            'score': self.score,
            'comment': self.comment,
            'manager': self.manager,
            'pre_ticket': self.pre_ticket
        }

    # pt_obj is the Pre_ticket object of the pre_ticket column (backref from Pre_ticket.ticket)

    def get_ticket(self, user_id):  # get ticket informations
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.score, t.status, t.read, t.responsable as res," \
                           "COALESCE(t.action,'') as action, COALESCE(t.comment,'') as comment, g.name as groupe_name, " \
                           "a.asset_ref,  a_u.cpe, c.description, COALESCE(c.cvss2,'') as cvss2, COALESCE(c.cvss3,'') as cvss3, COALESCE(c.links,'') as links, u.username as collab_name," \
                           "COALESCE(c.workarounds,'') as recommendation, COALESCE(pt.comment,'') as an_comment, COALESCE(c.published_at,'') as published_at " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join client_group g on  g.id = a.groupe " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "left join pre_ticket pt on  t.pre_ticket = pt.id " \
                           "left join user u on  u.id = t.responsable " \
                           "where t.id = %s AND s.manager = %s "

            arg = (self.id, user_id)
            cursor.execute(select_Query, arg)
            record = cursor.fetchone()
            # print('Ticket information: \n', record)
            return record
        except Exception as error:
            msg = 'Failed in Ticket.get_ticket(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def get_collab_ticket(self, user_id):  # get ticket informations
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.closed_at,'') as closed_at, COALESCE(t.created_at,'') as created_at, t.score, t.status, t.read," \
                           "COALESCE(t.action,'') as action, COALESCE(t.comment,'') as comment, g.name as groupe_name, " \
                           "a.asset_ref,  a_u.cpe, c.description, COALESCE(c.cvss2,'') as cvss2, COALESCE(c.cvss3,'') as cvss3, COALESCE(c.links,'') as links,  " \
                           "COALESCE(pt.recommendation,'') as recommendation, COALESCE(pt.comment,'') as an_comment " \
                           "FROM ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join service s on  a.service = s.id " \
                           "left join client_group g on  g.id = a.groupe " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "left join pre_ticket pt on  t.pre_ticket = pt.id " \
                           "where t.id = %s AND t.responsable = %s "

            arg = (self.id, user_id)
            cursor.execute(select_Query, arg)
            record = cursor.fetchone()
            # print('Ticket information: \n', record)
            return record
        except Exception as error:
            msg = 'Failed in Ticket.get_ticket(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)


class Ticket_history(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id', ondelete='CASCADE'))
    # usage is the asset_usage object of the usage_id column (backref from Asset_usage.tickets)
    opened_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    modified_at = db.Column(db.DateTime)
    action = db.Column(db.String(64))
    comment = db.Column(db.String(512))
    status = db.Column(db.Integer())
    responsable = db.Column(db.Integer)


class reset_password_token(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    # analyst_id = db.Column(db.Integer, db.ForeignKey('Analyst.id', ondelete='CASCADE'))
    token = db.Column(db.String(64))
    expiration_date = db.Column(db.DateTime, default=datetime.utcnow)


class Aut_alert(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    responsable = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(255))
    message = db.Column(db.Text)
    links = db.Column(db.Text)
    created_at = db.Column(db.DateTime)
    status = db.Column(db.Integer())
    solutions = db.Column(db.Text)
    published_on = db.Column(db.DateTime)
    score = db.Column(db.Float)


class Pre_ticket(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    usage_id = db.Column(db.Integer, db.ForeignKey('asset_usage.id', ondelete='CASCADE'))
    # usage is the asset_usage object of the usage_id column (backref from Asset_usage.pre_tickets)
    cve = db.Column(db.Integer(), db.ForeignKey('cve_temp.id', ondelete='RESTRICT'))
    # cve_obj is the cve_temp object of the cve column (backref from Cve_temp.pre_tickets)
    created_at = db.Column(db.DateTime, nullable=False)
    opened_at = db.Column(db.DateTime)
    treated_at = db.Column(db.DateTime)
    status = db.Column(db.Integer(), default=0)
    score = db.Column(db.Float)
    recommendation = db.Column(db.String(64))
    comment = db.Column(db.String(512))
    analysed_by = db.Column(db.Integer, db.ForeignKey('analyst.id'))
    # analyst is the Analyst object of the "analysed_by" column (backref from Analyst.pre_tickets)
    ticket = db.relationship('Ticket', backref='pt_obj', uselist=False)

    def get_pre_ticket(self, analyst_id):  # get pre_ticket informations
        try:
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True, buffered=True)

            select_Query = "select t.id, t.cve, COALESCE(t.opened_at,'') as opened_at, COALESCE(t.treated_at,'') as treated_at, COALESCE(t.created_at,'') as created_at, " \
                           "COALESCE(t.score,'') as score, t.status, COALESCE(t.recommendation,'') as recommendation, COALESCE(t.comment,'') as comment, g.name as groupe_name, " \
                           "a.asset_ref,  a_u.cpe, c.description, COALESCE(c.cvss2,'') as cvss2, COALESCE(c.cvss3,'') as cvss3, COALESCE(c.links,'') as links, c.mitigations, c.workarounds, " \
                           "FROM pre_ticket t " \
                           "left join asset_usage a_u on  t.usage_id = a_u.id " \
                           "left join asset a on  a_u.asset_id = a.id " \
                           "left join client_group g on  g.id = a.groupe " \
                           "left join cve_temp c on  t.cve = c.id " \
                           "where t.id = %s AND t.analysed_by = %s "

            arg = (self.id, analyst_id)
            cursor.execute(select_Query, arg)
            record = cursor.fetchone()
            # print('Ticket information: \n', record)
            return record
        except Exception as error:
            msg = 'Failed in Pre_ticket.get_ticket(): ' + str(error)
            debug_log('error', msg)
            return []
        finally:
            close_connection(connection)

    def __repr__(self):
        return '<Pre_ticket {}>'.format(self.id)


class Subscription(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    type = db.Column(db.Integer, db.ForeignKey('subs_plan.id', ondelete='RESTRICT'))
    # plan is the subs_plan object of the type (backref from Subs_plan.subscriptions)
    start_at = db.Column(db.DateTime)
    expire_on = db.Column(db.DateTime)
    status = db.Column(db.Integer(), default=1)
    client = db.relationship('Client_group', backref='subs_obj', uselist=False)

    def __repr__(self):
        return '<Subscription {}>'.format(self.id)


class Subs_plan(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    user_credits = db.Column(db.Integer())
    cpe_credits = db.Column(db.Integer())
    asset_credits = db.Column(db.Integer())
    payement = db.Column(db.String(64))
    subscriptions = db.relationship('Subscription', backref='plan', lazy='dynamic')

    def __repr__(self):
        return '<Subs_plan {}>'.format(self.id)


""" Functions/Decorators"""


def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                # Redirect the user to an unauthorized notice!
                return "Vous n'êtes pas autorisé à accéder à cette page!"
            return f(*args, **kwargs)

        return wrapped

    return wrapper


def owner_required(*ticket_id):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            try:
                connection = connect_to_db()
                cursor = connection.cursor(dictionary=True, buffered=True)

                select_Query = "select t.id FROM ticket t " \
                               "left join asset_usage a_u on  t.usage_id = a_u.id " \
                               "left join asset a on  a_u.asset_id = a.id " \
                               "left join service s on  asset.service = s.id " \
                               "where s.manager = %s AND t.id = %s "
                arg = (ticket_id,)
                cursor.execute(select_Query, arg)
                record = cursor.fetchone()
                # print('Ticket information: \n', record)
                if not record:
                    return "Vous n'êtes pas autorisé à accéder à cette page!"
            except Exception as error:
                msg = 'Failed in Ticket.get_ticket(): ' + str(error)
                debug_log('error', msg)
                return "Vous n'êtes pas autorisé à accéder à cette page!"
            finally:
                close_connection(connection)
                # Redirect the user to an unauthorized notice!

            return f(*args, **kwargs)

        return wrapped

    return wrapper


@event.listens_for(Ticket, 'after_insert')
def add_jira_ticket(mapper, connection, target):
    print("target", target)


class Ticket_notification(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id', ondelete='CASCADE'))
    status = db.Column(db.Integer())
    responsable = db.Column(db.Integer)
    manager = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow())


class Support(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    company = db.Column(db.Integer, db.ForeignKey('client_group.id', ondelete='CASCADE'))
    message = db.Column(db.String(250))
    subject = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow())
    attachment = db.Column(db.LargeBinary)


class Obsolescence(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    expiration_date = db.Column(db.DateTime)
    source = db.Column(db.String(45))
    patch = db.Column(db.String(45))
    version = db.Column(db.String(45))
    support = db.Column(db.String(45))
    eol = db.Column(db.String(45))
    latest = db.Column(db.String(45))
    releaseDate = db.Column(db.String(45))
    latestReleaseDate = db.Column(db.String(45))
    extendedSupport = db.Column(db.String(45))
    lts = db.Column(db.String(45))
    product_cpe = db.Column(db.String(45))

class Obso_exist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    id_cpe = db.Column(db.String(45))
    id_obso = db.Column(db.String(45))

class Notif_obsolescence(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    obsolescence_id = db.Column(db.Integer(), db.ForeignKey('obsolescence.id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    date = db.Column(db.DateTime)
    read = db.Column(db.Integer())



class License(db.Model):
    idLicense = db.Column(db.Integer(), primary_key=True)
    license = db.Column(db.String(250))
    client = db.Column(db.String(45))
    jwt = db.Column(db.String(360))
    id_server = db.Column(db.Integer())
    email = db.Column(db.String(45))
    last_call = db.Column(db.DateTime)

class Compte_technique(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))

class Agents_tokens(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    actif_name = db.Column(db.String(50))
    token = db.Column(db.String(250))


