""" This module contains all the routes of the application. This routes link URLs withe the associated view functions (handlers) """
import csv
import uuid
from audioop import cross
from builtins import list
from contextlib import closing
import secrets

import pandas as pd
from flask import render_template, flash, redirect, url_for, request, session, jsonify, abort
from flask_cors import cross_origin
from flask_restx.cors import crossdomain
from flask import Response
from API.flask_app.app import app, db
from database.client import get_clients, get_clients_info, get_analysts
from flask_login import current_user, login_user, logout_user, login_required
from API.flask_app import models as m
from API.flask_app.models import requires_roles, owner_required
from werkzeug.utils import secure_filename
from API.authy.utils import create_user, send_authy_token_request, verify_authy_token
from authy import AuthyApiException
from API.flask_app.decorators import verify_authy_request, login_verified

from flask import Flask, json, g, request
from alert.sender import send_mime_mail_assign_ticket, send_mime_mail
from debug.debug import debug_log
from parsers.uni_parser import normalise_cpe_name
import os
import pathlib
from flask_paginate import Pagination, get_page_parameter
from flask_jwt_extended import JWTManager, jwt_required, get_jwt, get_jwt_identity, verify_jwt_in_request
import datetime as dti
import pandas as pf
from database.client import get_asset_id
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pyotp
import smtplib, ssl
from sqlalchemy import or_, desc
from dateutil.relativedelta import *
from email.mime.base import MIMEBase
from email import encoders
from collections import defaultdict
import requests
import ast
import re

def send_mail_verif(receiver, message):
    debug_log('debug', 'Start send_mime_mail()')
    try:
        """ Setting the alert sending datetime  """
        now = datetime.now()
        published_on = now.strftime("%Y-%m-%d %H:%M:%S")

        port = 465  # For SSL
        # port = 587  # For TLS
        # password = input('Mot de passe : ')
        password = 'sclejogluiokgmwn'
        sender_email = 'pgv.brightway@gmail.com'

        # Create a secure SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
            # server.starttls(context=context) # to use TLS
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver, message)
            print('mail sent successfully to: ', receiver)

        # Using smtp without ssl (NOT WORKING)
        # with smtplib.SMTP("smtp.gmail.com",port=25) as server: # Testing smtp without ssl
        # server.connect("smtp.gmail.com")
        # server.helo()
        # server.sendmail(sender_email, receiver, message.as_string())

        msg = f"""mail sent successfully to {receiver}"""
        debug_log('info', msg)



    except Exception as e:
        msg = 'Failed in send_mime_mail(): ' + str(e)
        debug_log('error', msg)
        print('Error send_mime_mail: ', str(e))
        published_on = None
    finally:
        debug_log('debug', 'End send_mime_mail()')
        return published_on


@app.route('/add-ticket', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def create_ticket_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    cpe = request.json.get("cpe")
    special_characters = "!@#$%^&*()+?=<>/"
    print('cpe', cpe)
    if not cpe:
        print('cpe', cpe)
        print("le champ produit est obligatoire ")
        return jsonify({"erreur": "le champ produit est obligatoire "})
    asset = request.json.get("asset")
    print('asset', asset)
    if not asset:
        print('asset', asset)
        print("le champ actif est obligatoire ")
        return jsonify({"erreur": "le champ actif est obligatoire "})

    score = float(request.json.get("score"))
    asset_instance = m.Asset.query.filter_by(asset_ref=asset).first_or_404()
    asset_usage = m.Asset_usage.query.filter_by(cpe=cpe, asset_id=asset_instance.id).first_or_404()
    created_at = dti.datetime.now()
    ticket = m.Ticket(usage_id=asset_usage.id, created_at=created_at, score=float(score), manager=user.id)
    db.session.add(ticket)
    db.session.commit()
    return jsonify({"sucess": "ticket added successfully"}), 201


@app.route('/add-ticket-all-asset', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def create_all_tickets_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    assets = user.get_client_assets()
    special_characters = "!@#$%^&*()+?=<>/"
    liste = []
    cpe = request.json.get('cpe')
    liste.append(cpe)
    expectedResult = [d for d in assets if d['cpe'] in liste]
    cve = request.json.get("cve")
    print("cve", cve)
    if not cve or (any(c in special_characters for c in cve)):
        print("cve", cve)
        print("le champ cve est obligatoire ou ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ cve est obligatoire ou ne doit pas contenir de caract�res sp�ciaux"})

    action = request.json.get("action")
    print("action", action)
    if any(c in special_characters for c in action):
        print("action", action)
        print("le champ action ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ action ne doit pas contenir de caract�res sp�ciaux"})
    comment = request.json.get("comment")
    print("comment", comment)
    if any(c in special_characters for c in comment):
        print("comment", comment)
        print("le champ comment ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ comment  ne doit pas contenir de caract�res sp�ciaux"})
    info = request.json.get("info")
    print("info", info)
    if any(c in special_characters for c in info):
        print("info", info)
        print("le champ info ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ info ne doit pas contenir de caract�res sp�ciaux"})
    due_date = request.json.get("due_date")
    print("due_date", due_date)

    title = request.json.get("title")
    print("title", title)
    if any(c in special_characters for c in title):
        print("title", title)
        print("le champ title ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ title ne doit pas contenir de caract�res sp�ciaux"})
    description = request.json.get("description")
    print("descr", description)
    if any(c in special_characters for c in description):
        print("descr", description)
        print("le champ description  ne doit pas contenir de caract�res sp�ciaux")
        return jsonify({"erreur": "le champ description ne doit pas contenir de caract�res sp�ciaux"})
    cvss = request.json.get("cvss")
    print("cvss", cvss)
    print("cve", cve, "title", title, "description", description, "cvss", cvss)

    cve_tmp = m.Cve_temp(id=cve, title=title,
                         description=description, cvss2=float(cvss))
    db.session.add(cve_tmp)
    db.session.commit()
    created_at = dti.datetime.now()

    for element in expectedResult:
        asset_instance = m.Asset.query.filter_by(asset_ref=element['asset_ref']).first_or_404()
        score = float(cvss) * asset_instance.importance * 2.5
        asset_usage = m.Asset_usage.query.filter_by(cpe=cpe, asset_id=asset_instance.id).first_or_404()
        ticket = m.Ticket(usage_id=asset_usage.id, cve=cve_tmp.id, created_at=created_at, score=float(score),
                          manager=user.id)
        ticket.action = action
        ticket.comment = comment
        ticket.info = info
        ticket.due_date = due_date
        db.session.add(ticket)
        db.session.commit()
    return jsonify({"sucess": "ticket added successfully"}), 201


""" trying token_required"""
import jwt
from functools import wraps
from flask import current_app

"""second method for authentication"""
import flask_praetorian

""" 3rd method of authentification"""
from flask_jwt_extended import create_access_token


# Create a route to authenticate your users and return JWT Token. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/token", methods=["POST"])
@cross_origin()
def create_token():
    # get username input
    # get password input
    username = request.json.get("username")
    password = request.json.get("password")

    user = m.User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        # the user was not found on the database
        return jsonify({"msg": "Identifiant ou mot de passe incorrect"}), 401

    # create a new token with the user id inside
    expires = dti.timedelta(days=2)
    access_token = create_access_token(identity=user.id, expires_delta=expires)
    role = user.role
    l1 = []

    if role == "ad_user":
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        company_name = client_group.name
        company_description = client_group.type

        response = {"token": access_token, "user_id": user.id, "username": user.username, "nom": user.nom,
                    "prenom": user.prenom, "role": role, 'email': user.email,
                    'country_code': user.country_code, 'phone': user.phone, 'company': company_name,
                    'company_desc': company_description}
        print('response', response)
        return jsonify(response)
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    company_name = client_group.name
    company_description = client_group.type

    response = {"token": access_token, "user_id": user.id, "username": user.username, "nom": user.nom,
                "prenom": user.prenom, "role": role, 'email': user.email,
                'country_code': user.country_code, 'phone': user.phone, 'company': company_name,
                'company_desc': company_description}
    print('response', response)
    return jsonify(response)


@app.route("/login2fa", methods=["POST"])
@cross_origin()
@jwt_required()
def create_2fa():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    secret = user.secret_2fa
    print('opt before', request.json.get("otp"))
    otp = int(request.json.get("otp"))
    print('otp after', otp)

    if pyotp.TOTP(secret).verify(otp):
        user.first_login = 1
        db.session.add(user)
        db.session.commit()

        return jsonify({"msg": "authentification r�ussie"})
    return jsonify({"msg": "erreur d'authentification"}), 401


@app.route("/user-overview/<id>", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def get_user_overview(id):
    current_user_id = get_jwt_identity()
    print("cu", current_user_id)
    print("id", id)
    if int(id) == int(current_user_id):
        user = m.User.query.filter_by(id=current_user_id).first_or_404()
        assets = m.Asset.query.filter_by(manager=current_user_id).all()
        tickets = user.get_tickets()
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        services = client_group.get_services()
        unread_tickets = user.get_unread_tickets()
        return jsonify(
            {'nb_actifs': len(assets), 'nb_tickets': len(tickets),
             'nb_services': len(services), 'count_unread_tickets': len(unread_tickets)})
    else:
        return jsonify({"error": "you do not have the permission"}), 403


import datetime
from itertools import groupby
from operator import itemgetter

"""table_vuls"""


@app.route('/list-vuls_dash', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_vuls():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    tickets = user.get_tickets()
    assets = user.get_client_assets()
    services = client_group.get_subscription_info()
    Ass = m.Asset.query.filter_by(manager=current_user_id).all()
    vuls = []
    out2_liste_vuls = []
    liste_vuls = []
    liste_vlus2 = []
    liste_vuls_chart1 = []
    liste_vuls_chart2 = []
    liste_vuls_chart = []
    liste_vuls_chart3 = []
    liste_service_pie = []
    nombre_actif = []
    liste_pie1 = []
    liste1 = []
    out8 = []
    out5_vuls = []
    out10 = []
    out9 = []
    out1 = []
    out2 = []
    out3 = []
    out4 = []
    out5 = []
    out6 = []
    out7 = []
    outputDelta = []
    listeSorted = []
    listeDelta = []
    listeTaux = []
    listeMonth = []
    deltaTime = 0
    somme = 0
    delta = 0
    listeDate = []
    listMonth = []
    if len(tickets) > 0:
        for n in tickets:
            dict_taux = {}
            dict_delta = {}
            dict_re = {}
            dict_chart4 = {}
            dict_chart1 = {}
            dict_chart2 = {}
            dict_chart3 = {}
            dict_actif = {}
            dict_final = {}
            dict_re['cve'] = n['cve']
            dict_re['id'] = n['id']
            dict_re['date'] = n['created_at']
            if n['score']:
                dict_re['score'] = n['score']
            else:
                dict_re['score'] = 0
            dict_re['asset_ref'] = n['asset_ref']
            dict_actif['cve'] = n['cve']
            dict_actif['asset_ref'] = n['asset_ref']
            dict_chart1['cve'] = n['cve']
            dict_chart2['cve'] = n['cve']
            if n['score']:
                dict_chart2['score'] = round(n['score'])
            else:
                dict_chart2['score'] = 0
            dict_chart3['cve'] = n['cve']
            dict_chart3['status'] = n['status']
            dict_chart1['month'] = dti.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S').strftime("%B")
            vuls.append(dict_re)
            liste_vuls_chart1.append(dict_chart1)
            liste_vuls_chart.append(dict_chart2)
            liste_vuls_chart3.append(dict_chart3)
            nombre_actif.append(dict_actif)
            if n['closed_at']:
                dict_delta['open'] = dti.datetime.strptime(n['opened_at'], '%Y-%m-%d %H:%M:%S').strftime("%m")
                dict_delta['close'] = dti.datetime.strptime(n['closed_at'], '%Y-%m-%d %H:%M:%S').strftime("%m")
                dict_delta['id'] = n['id']
                listeDate.append(dict_delta)
        vuls_2 = sorted(vuls, key=itemgetter('cve'))
        for element in Ass:
            dict1 = {}
            dict1['asset_ref'] = element.asset_ref
            dict1['status'] = element.status
            liste_pie1.append(dict1)
        for element in listeDate:
            delta = (int(element['close']) - int(element['open'])) * 720
            dict_taux['delta'] = delta
            dict_taux['Month'] = element['open']
            listeTaux.append(dict_taux)

        listeSorted = sorted(listeTaux, key=itemgetter("Month"))
        for i, j in groupby(listeSorted, key=itemgetter("Month")):
            outputDelta.append(list(j))
        for i in outputDelta:
            for j in i:
                somme = somme + j['delta']
                dict_final['Month'] = j['Month']
            taux = round(somme / len(tickets), 2)

            print(taux)
            dict_final['taux'] = taux
            listeDelta.append(dict_final['taux'])
            listeMonth.append(dict_final['Month'])
        for s in listeMonth:
            month_name = dti.datetime(1, int(s), 1).strftime("%B")
            listMonth.append(month_name)
        print("vuls_2", vuls_2)
        for e, f in groupby(vuls_2, key=itemgetter("cve")):
            out2_liste_vuls.append(list(f))
        liste_vuls.sort(key=lambda date: date.created_at)
        try:
            liste_vuls_chart4 = sorted(liste_vuls_chart3, key=itemgetter('status'))
        except Exception:
            liste_vuls_chart4 = liste_vuls_chart3
        finally:
            liste_vuls_chart4 = liste_vuls_chart3
        liste1 = sorted(liste_pie1, key=itemgetter('status'))
        liste_vuls = vuls[0:5]
        outputList = []
        outputList2 = []
        outputList3 = []
        outputList4 = []
        outputList5 = []
        liste_vuls_chart2 = sorted(liste_vuls_chart, key=itemgetter('score'))
        for a, b in groupby(liste_vuls_chart1, key=itemgetter("month")):
            outputList.append(list(b))
        for l, s in groupby(liste1, key=itemgetter("status")):
            outputList5.append(list(s))
        for e, f in groupby(liste_vuls_chart4, key=itemgetter("status")):
            outputList3.append(list(f))
        for n, k in groupby(liste_vuls_chart2, key=itemgetter("score")):
            outputList2.append(list(k))
        for h, j in groupby(nombre_actif, key=itemgetter("cve")):
            outputList4.append(list(j))
        for elemen5 in outputList5:
            for e5 in elemen5:
                out9.append(e5['status'])
                break
            taille = len(elemen5)
            out10.append(taille)
        for elemen2 in outputList2:
            for e2 in elemen2:
                out3.append(e2['score'])
                break
            taille = len(elemen2)
            out4.append(taille)
        for elemen3 in outputList3:
            for e3 in elemen3:
                out5.append(e3['status'])
                break
            taille = len(elemen3)
            out6.append(taille)
        for element in outputList:
            for e in element:
                out1.append(e['month'])
                break
            taille = len(element)
            out2.append(taille)
        for elemen4 in outputList4:
            for e4 in elemen4:
                out7.append(e4['cve'])
                break
            taille = len(elemen4)
            out8.append(taille)
        for e in out2_liste_vuls:
            dict_re_vuls = {}
            for x in e:
                dict_re_vuls['cve'] = x['cve']
                dict_re_vuls['score'] = x['score']
                break
            taille = len(e)
            dict_re_vuls['nb_actifs_cve'] = taille
            out5_vuls.append(dict_re_vuls)
            try:
                out5_vuls = sorted(out5_vuls, key=itemgetter('score'), reverse=True)
            except:
                out5_vuls = out5_vuls
            finally:
                out5_vuls = out5_vuls
        out5_vuls = out5_vuls[0:5]
    print("res", listMonth)
    return jsonify({"nombre-actif": out8, "liste_vuls": out5_vuls, "liste_vuls_pie_y": out10, "liste_vuls_pie_x": out9,
                    "liste_vuls3_chart3_x": out5, "liste_vuls3_chart3_y": out6, "liste_vuls_chart1_x": out1,
                    "liste_vuls_chart1_y": out2, "liste_vuls2_chart2_x": out3, "liste_vuls2_chart2_y": out4,
                    "listMonth": listMonth, "listeDelta": listeDelta})


""" Ticket read or no """


@app.route('/modify-ticket-status', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def modify_ticket_status_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket_id = request.json.get('ticket_id')

    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_ticket(user.id)

    if t:
        ticket.read = 1
        db.session.commit()
        return {
            "message": "success"
        }
    else:
        return {
            "message": "error"
        }, 404


@app.route('/modify-ticket-status-collab', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def modify_ticket_status_collab_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket_id = request.json.get('ticket_id')
    print('ticket_id', ticket_id)
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_collab_ticket(user.id)
    print('t', t)
    if t:
        ticket.read = 1
        db.session.commit()
        return {
            "message": "success"
        }
    else:
        return {
            "message": "error"
        }, 201


@app.route('/add-tickets-csv', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def upload_csv_tickets():
    file = request.files['file']
    filename = secure_filename(file.filename)
    print("filename", filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    with open(file_path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        tickets_list = []
        for row in csv_reader:
            print(len(row))  # debug
            if len(row) == 13:
                if line_count == 0:
                    print(f'Column names are {", ".join(row)}')
                    line_count += 1
                    # print('type of csv line: ',type(row)) # debug
                elif not row[0] or not row[1]:
                    return jsonify({"erreur": "first columns are mandatory"})
                else:
                    asset_ref = row[0]
                    print("asset_ref", asset_ref)
                    cpe_name = row[1]
                    print("nom du produit", cpe_name)
                    cpe_version = row[2]
                    print("version du produit", cpe_version)
                    cpe_producer = row[3]
                    print("fournisseur du produit", cpe_producer)
                    cve = row[4]
                    print("vul", cve)
                    cvss = row[5]
                    print("cvss", cvss)
                    title = row[6]
                    print("title", title)
                    score = row[7]
                    print("score", score)
                    action = row[8]
                    print("action", action)
                    comment = row[9]
                    print("comment", comment)
                    info = row[10]
                    print("info", info)
                    deadline = row[11]
                    print("deadline", deadline)
                    description = row[12]
                    print("description", description)
                    if not deadline:
                        deadline = datetime.now() + datetime.timedelta(days=7)

                    special_characters = "!@#$%^&*()+?=<>/"
                    if (any(c in special_characters for c in cve)):
                        return jsonify({"error": "le champ cve ne peut pas accepter les caract�res sp�ciaux"})
                    if (any(c in special_characters for c in description)):
                        return jsonify({"error": "le description cve ne peut pas accepter les caract�res sp�ciaux"})
                    if (any(c in special_characters for c in info)):
                        return jsonify({"error": "le champ info ne peut pas accepter les caract�res sp�ciaux"})
                    if (any(c in special_characters for c in comment)):
                        return jsonify({"error": "le champ comment ne peut pas accepter les caract�res sp�ciaux"})
                    if (any(c in special_characters for c in action)):
                        return jsonify({"error": "le champ action ne peut pas accepter les caract�res sp�ciaux"})
                    try:
                        cpe = m.Client_cpe.query.filter_by(producer=cpe_producer, name=cpe_name,
                                                           version=cpe_version).first_or_404()
                        print('cpe instance', cpe)
                        asset = m.Asset.query.filter_by(asset_ref=asset_ref, manager=user.id).first_or_404()
                        print('asset instance', asset)
                        cve_tmp = m.Cve_temp(id=cve, title=title,
                                             description=description, cvss2=float(cvss))
                        print("cve_temp", cve_tmp)
                        db.session.add(cve_tmp)
                        db.session.commit()
                        print("vul added")

                        asset_usage = m.Asset_usage.query.filter_by(cpe=cpe.id_cpe, asset_id=asset.id).first_or_404()
                        print("asset_usage", asset_usage)
                        created_at = dti.datetime.now()
                        print("created_at", created_at)
                        date_time_obj = dti.datetime.strptime(deadline, '%d/%m/%y')
                        ticket = m.Ticket(usage_id=asset_usage.id, cve=cve_tmp.id, created_at=created_at,
                                          score=float(score), manager=user.id,
                                          due_date=date_time_obj)
                        print("ticket", ticket)
                        if comment:
                            ticket.comment = comment
                        if info:
                            ticket.info = info
                        if action:
                            ticket.action = action

                        db.session.add(ticket)
                        db.session.commit()
                        return jsonify({"success": "ticket added successfully"})
                    except Exception:
                        return jsonify({"error": "produit ou actif inexistant"})
            else:
                return jsonify({"error": "missed columns"})


"""list all unread tickets """


@app.route('/list-unread-tickets', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_tickets_unread_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    tickets = user.get_unread_tickets()
    count = len(tickets)

    return jsonify({"count": count})


"""List all assets pour ad_user"""


@app.route('/asset-api/list-all')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def ad_assets_api():
    """ Show all assets of the client (user) """
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        return jsonify("chaine vide"), 403
    else:
        assets = m.Asset.query.filter_by(manager=current_user_id).all()
        liste_assets = []
        for element in assets:
            dict_asset = {}
            dict_asset['id'] = element.id
            dict_asset['asset_ref'] = element.asset_ref
            dict_asset['groupe'] = element.groupe
            dict_asset['status'] = element.status
            if element.importance == 1:
                importance = 'Mineur'
            elif element.importance == 2:
                importance = 'Important'
            elif element.importance == 3:
                importance = 'Majeur'
            else:
                importance = 'Critique'

            dict_asset['importance'] = importance
            service = m.Service.query.filter_by(id=element.service).first_or_404()
            dict_asset['service'] = service.name
            if element.responsable:
                user_res = m.User.query.filter_by(id=element.responsable).first_or_404()

                dict_asset['responsable'] = user_res.username
            else:
                dict_asset['responsable'] = ""
            liste_assets.append(dict_asset)
        return jsonify(liste_assets)


@app.route('/product-api/list-all')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def products_api():
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        print('hrllo')
        assets = user.get_assets()
        tickets = m.Ticket.query.filter_by(responsable=current_user_id).all()
        if (tickets):
            liste1 = []
            for ticket in tickets:
                liste1.append(ticket.usage_id)
            liste2 = []
            liste3 = []
            for element in liste1:
                usage_instance = m.Asset_usage.query.filter_by(id=element).first_or_404()
                liste3.append(usage_instance)
                liste2.append(usage_instance.asset_id)

            l2 = []
            for usage in liste3:
                dict2 = {}
                cpe = m.Client_cpe.query.filter_by(id_cpe=usage.cpe).first_or_404()
                asset = m.Asset.query.filter_by(id=usage.asset_id).first_or_404()
                dict2['cpe_readable'] = cpe.name
                dict2['producer'] = cpe.producer
                dict2['asset_ref'] = asset.asset_ref
                l2.append(dict2)
            return jsonify(l2)

            #expectedResult = [d for d in assets if d['id'] in liste2]
            #l1 = []
            #if expectedResult:
            #    for element in expectedResult:
            #        dict1 = {}
            #        if (element['id_cpe']):
            #            cpe = m.Client_cpe.query.filter_by(id_cpe=element['id_cpe']).first_or_404()
            #            dict1['cpe_readable'] = cpe.get_full_product_name()
            #            dict1['producer'] = element['producer']
            #            dict1['asset_ref'] = element['asset_ref']
            #            l1.append(dict1)
            #    return jsonify(l1)
        else:
            return jsonify({"msg": "error"})
    else:
        assets = user.get_client_assets()
        tickets = m.Ticket.query.filter_by(manager=current_user_id).all()
        if (tickets):
            liste1 = []
            for ticket in tickets:
                liste1.append(ticket.usage_id)
            liste2 = []
            liste3 = []
            for element in liste1:
                usage_instance = m.Asset_usage.query.filter_by(id=element).first_or_404()
                liste3.append(usage_instance)
                liste2.append(usage_instance.asset_id)
            expectedResult = [d for d in assets if d['id'] in liste2]
            l2 = []
            for usage in liste3:
                dict2 = {}
                cpe = m.Client_cpe.query.filter_by(id_cpe=usage.cpe).first_or_404()
                asset = m.Asset.query.filter_by(id=usage.asset_id).first_or_404()
                dict2['cpe_readable'] = cpe.name
                dict2['producer'] = cpe.producer
                dict2['asset_ref'] =asset.asset_ref
                l2.append(dict2)
            return jsonify(l2)
            #l1 = []
            #if expectedResult:
            #    for element in expectedResult:
            #        dict1 = {}
            #        if (element['cpe']):
            #            cpe = m.Client_cpe.query.filter_by(id_cpe=element['cpe']).first_or_404()
            #            dict1['cpe_readable'] = cpe.get_full_product_name()
            #            dict1['producer'] = element['producer']
            #            dict1['asset_ref'] = element['asset_ref']
            #            l1.append(dict1)
            #    return jsonify(l1)
        else:
            return jsonify({"msg": "error"})


@app.route('/tickets-history/list-all')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def tickets_history_api():
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        tickets = user.get_closed_tickets_team()
        return jsonify(tickets)
    else:
        tickets = user.get_closed_tickets()
        return jsonify(tickets)


@app.route('/tickets-history-team/list-all')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def tickets_history_team_api():
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        return jsonify("chaine vide")
    else:
        tickets = user.et_closed_tickets_team()
        return jsonify(tickets)


"""modify asset per ad_user"""


@app.route('/asset-api/update', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
# @login_required
# @requires_roles('ad_user')
def modify_asset_api():
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    # form.manager.choices = [(u.id, u.username) for u in client_group.users]
    services = client_group.get_services()
    asset_ref = request.json.get('asset_ref')
    importance = request.json.get('importance')
    service = request.json.get('service')
    print('services', services)
    list_ser = [service]
    expectedResult = [d for d in services if d['name'] in list_ser]
    print('expected', expectedResult)
    collab = request.json.get('collab')
    asset = m.Asset.query.filter_by(asset_ref=asset_ref, groupe=client_group.id).first()

    if asset:
        if importance:
            if importance == 'Mineur':
                importance_val = 1
            elif importance == 'Important':
                importance_val = 2
            elif importance == 'Majeur':
                importance_val = 3
            else:
                importance_val = 4
            asset.importance = importance_val
        if expectedResult:
            asset.service = expectedResult[0]['id']

        if collab:
            user_collab = m.User.query.filter_by(username=collab).first_or_404()
            asset.responsable = user_collab.id
        db.session.commit()
        return jsonify({"success": "asset modifi� avec succ�s"})
    else:
        return jsonify({"error": "asset introuvable"})


""" modify ticket api """


@app.route('/ticket-modify-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def modify_ticket_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket_id = request.json.get('ticket_id')
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_ticket(user.id)
    now = dti.datetime.now()
    modifiedAt = now.strftime("%Y-%m-%d %H:%M:%S")
    if t:
        cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
        if cpe:
            t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
            # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Fermé',
                print('date', dti.datetime.now())
                t['closed_at'] = dti.datetime.now()
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Traité'
        # if request.method == 'POST':
        status = request.json.get('status')
        print('status', status)
        if status == "Fermé":
            s = -1
        elif status == "Traité":
            s = 2
        elif (status == "En cours de traitement"):
            s = 1
        else:
            s = 0
        ticket_hist = m.Ticket_history(ticket_id=ticket_id, status=s, modified_at=modifiedAt)
        ticket.status = s
        if not ticket.opened_at and status == 1:
            now = dti.datetime.now()
            ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
            ticket_hist.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
        elif s == -1:
            now = dti.datetime.now()
            print('now', now)
            ticket.closed_at = now.strftime("%Y-%m-%d %H:%M:%S")
            ticket_hist.closed_at = now.strftime("%Y-%m-%d %H:%M:%S")
        if request.json.get('action'):
            ticket.action = request.json.get('action')
            ticket_hist.action = request.json.get('action')
        if request.json.get('comment'):
            ticket.comment = request.json.get('comment')
            ticket_hist.comment = request.json.get('comment')

        db.session.add(ticket_hist)
        db.session.commit()

        ticket_notification = m.Ticket_notification(
            ticket_id=ticket.id,
            status=s,
            responsable=ticket.responsable,
            manager=ticket.manager
        )
        db.session.add(ticket_notification)
        db.session.commit()

        return {
            "message": "success"
        }
    else:
        return {
            "message": "error"
        }, 404


@app.route('/ticket-modify-api-collab', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def modify_ticket_api_collab():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket_id = request.json.get('ticket_id')
    print(ticket_id, 'ticket_id')
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_collab_ticket(user.id)
    if t:
        cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
        if cpe:
            t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
            # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Ferm�',
                print('date', datetime.now())
                t['closed_at'] = datetime.now()
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Trait�'
        # if request.method == 'POST':
        status = request.json.get('status')
        print('status', status)
        if status == "Ferm�":
            s = -1
        elif status == "Trait�":
            s = 2
        elif (status == "En cours de traitement"):
            s = 1
        else:
            s = 0
        ticket.status = s
        ticket.read = 1
        if not ticket.opened_at and status == 1:
            now = dti.datetime.now()
            ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
        elif s == -1:
            now = dti.datetime.now()
            print('now', now)
            ticket.closed_at = now.strftime("%Y-%m-%d %H:%M:%S")
        if request.json.get('action'):
            if len(request.json.get('action')) > 0:
                ticket.action = request.json.get('action')
        if request.json.get('comment'):
            if len(request.json.get('comment')) > 0:
                ticket.comment = request.json.get('comment')
        db.session.commit()
        return {
            "message": "success"
        }
    else:
        return {
            "message": "error"
        }, 404


"""asset import per ad_user """


@app.route('/import-asset-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def import_asset_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_extension = pathlib.Path(filename).suffix
    if file_extension not in app.config['ALLOWED_EXTENSIONS']:
        flash('Format de fichier non support�!')
    else:
        file_data = request.files[file]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_data.save(file_path)
        """ getting clients info (products credit information)"""
        client = m.Client_group.query.filter_by(id=user.groupe).first()
        client_info = client.get_all_info()
        cpe_credits = int(client_info['cpe_credits']) - int(
            client_info['nb_products'])  # calculate remaining cpe credits
        """ Importing new assets"""
        import_results = client.import_assets(file_path, cpe_credits)  # remaining product credits
        """ Showing import results"""

        if import_results['nb_cpes'] != import_results['cpes']:
            return {
                "message": "duplicated_product"
            }
        if import_results['cpe_credits'] == 0:
            return {
                "message": "Vous avez atteint la limite de produits � ajouter"
            }
        client_info = client.get_all_info()  # Getting product credits information after the import
        return {
            "message": "success"
        }


""" *** Assets Management *** """
""" Show assets for user """


# asset_list api get_s_user_ad_user
# @requires_roles('s_user', 'ad_user')
@app.route("/asset-api-get", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def assets_get_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    assets = user.get_assets()
    asset_list = []
    if len(assets) > 0:
        for element in assets:
            print("element", element)
            dict_asset = {}
            if element['id_cpe']:
                producer = element['producer'].replace('_', ' ')
                name = element['name'].replace('_', ' ')
                cpe = producer.title() + ' ' + name.title() + ' '
                dict_asset['producer'] = producer
                dict_asset['version'] = element['version']
                dict_asset['name'] = name
                """ replace '*' version by '' """
                if element['version'] != '*':
                    cpe += element['version']
                dict_asset['cpe'] = cpe
                dict_asset['asset_ref'] = element['asset_ref']
                dict_asset['id_cpe'] = element['id_cpe']
                asset_list.append(dict_asset)
    print("asset_list", asset_list)
    return jsonify(asset_list)


# tickets_list api get_ad_user
# @requires_roles('ad_user')
@app.route("/tickets-api-get", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def tickets_get_api():
    # if not current_user.is_anonymous:

    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        tickets = user.get_user_tickets()
    else:
        tickets = user.get_tickets()
    print('tickets', tickets)
    return jsonify(tickets)


@app.route("/user-tickets-api-get", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def collab_tickets_get_api():
    # if not current_user.is_anonymous:

    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    print("user", user)
    tickets = user.get_user_tickets()
    print("tickets", tickets)
    return jsonify(tickets)


# users_list_api get_ad_user
@requires_roles('ad_user')
@app.route("/users-api-get", methods=["GET"])
def users_get_api():
    user = m.User.query.filter_by(username=current_user.username).first_or_404()
    users_info = user.get_users_info()
    return jsonify(users_info)


@app.route("/user-delete",methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def user_delete():
    user_target_id = request.json.get('user_id')
    print("user_target_id", user_target_id)
    user_target = m.User.query.filter_by(id=user_target_id).first_or_404()
    print("user_target", user_target)
    db.session.delete(user_target)
    db.session.commit()
    return jsonify({'success': "Suppression du collaborateur effectu�e avec succ�s"}), 201

""" Service Management"""
""" Show all services for Admin"""


@app.route("/service/lists", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_services_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    services = client_group.get_services()
    service_list = []
    if user.role == "ad_user":

        for s in services:
            user_responsable_username = ""
            service = m.Service.query.filter_by(id=s['id']).first_or_404()
            if service.responsable:
                user_responsable = m.User.query.filter_by(id=service.responsable).first_or_404()
                user_responsable_username = user_responsable.username
            service_list.append({'name': s['name'], 'manager': s['manager'], 'responsable': user_responsable_username,
                                 'localisation': s['localisation'], 'desciption': s['description'], 'id': s['id']})
    print('service list', service_list)
    return jsonify(service_list)


@app.route("/obso-products-client", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def get_obso_client():
    products = m.Obso_exist.query.all()
    obso_list = []
    for product in products:
        obso = m.Obsolescence.query.filter_by(id=product.id_obso).first()
        obso_dict = {
            "id": str(product.id),
            "expiration_date": str(obso.expiration_date),
            "source": obso.source,
            "patch": obso.patch,
            "version": obso.version,
            "support": obso.support,
            "eol": obso.eol,
            "latest": obso.latest,
            "releaseDate": obso.releaseDate,
            "latestReleaseDate": obso.latestReleaseDate,
            "extendedSupport": obso.extendedSupport,
            "lts": obso.lts,
            "product_cpe": obso.product_cpe
        }
        obso_list.append(obso_dict)
    return jsonify(obso_list)
@app.route('/detail-obso-client-api/<id_obso>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def detail_obso_client(id_obso):
    obso = m.Obso_exist.query.filter_by(id=int(id_obso)).first()
    dict_obso = {}
    if obso is None:
        return jsonify({'error': 'Obsolete certificate not found.'}), 404
    obsolete = m.Obsolescence.query.filter_by(id=obso.id_obso).first()
    dict_obso['eol'] = obsolete.eol
    dict_obso['version'] = obsolete.version
    dict_obso['name'] = obsolete.product_cpe
    dict_obso['support'] = obsolete.support
    dict_obso['releaseDate'] = obsolete.releaseDate
    dict_obso['latest'] = obsolete.latest
    return jsonify(dict_obso)



@app.route("/upcoming-obso-products-client", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def get_upcoming_obso_client():
    products = m.Notif_obsolescence.query.all()
    obso_list = []
    for product in products:
        respo = m.User.query.filter_by(id=product.user_id).first()
        obso = m.Obsolescence.query.filter_by(id=product.obsolescence_id).first()
        obso_dict = {
            "expiration_date": str(obso.expiration_date),
            "id": str(obso.id),
            "source": obso.source,
            "patch": obso.patch,
            "version": obso.version,
            "support": obso.support,
            "eol": obso.eol,
            "latest": obso.latest,
            "releaseDate": obso.releaseDate,
            "latestReleaseDate": obso.latestReleaseDate,
            "extendedSupport": obso.extendedSupport,
            "lts": obso.lts,
            "product_cpe": obso.product_cpe,
            "responsable": respo.username
        }
        obso_list.append(obso_dict)
        return jsonify(obso_list)

@app.route('/liste-produit-client', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_produits_client():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    products = m.Client_cpe.query.all()

    listProduits = []
    for product in products:
        usage = m.Asset_usage.query.filter_by(cpe=product.id_cpe).first()
        asset_id = usage.asset_id if usage else None
        asset = m.Asset.query.filter_by(id=asset_id).first()
        if asset:
         dict_product= {
            'name': product.name,
            'producer': product.producer,
            'version': product.version,
            'asset_ref': asset.asset_ref,
            'asset_id': asset_id
         }
         if user.role == "ad_user":
             listProduits.append(dict_product)
         elif asset.responsable == current_user_id:
             listProduits.append(dict_product)

    return jsonify(listProduits)


from datetime import datetime

@app.route('/notif-obsolescence/<int:notif_id>', methods=['PUT'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def update_notif_obsolescence(notif_id):
    notif = m.Notif_obsolescence.query.filter_by(id=notif_id).first()
    if notif:
        notif.read = 1
        db.session.commit()
        return jsonify({'message': 'Notification updated successfully!'})
    else:
        return jsonify({'message': 'Notification not found.'}), 404

@app.route("/get-obso-client-notif", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def obso_client():
    products = m.Notif_obsolescence.query.all()
    obso_list3 = []
    for product in products:
        respo = m.User.query.filter_by(id=product.user_id).first()
        obso = m.Obsolescence.query.filter_by(id=product.obsolescence_id).first()
        obso_dict = {
            "id": str(product.id),
            "expiration_date": str(obso.expiration_date),
            "eol": obso.eol,
            "product_cpe": obso.product_cpe,
            "read": product.read
        }
        obso_list3.append(obso_dict)
    # trier la liste par date de fin de vie ("eol")
    sorted_obso_list = sorted(obso_list3, key=lambda x: datetime.strptime(x['eol'], "%Y-%m-%d"))

    # s�lectionner les trois premiers �l�ments de la liste tri�e
    upcoming_obso_list3 = sorted_obso_list[:3]

    return jsonify(upcoming_obso_list3)

@app.route("/abonnement-detail-get-api", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def abonnement_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client = m.Client_group.query.filter_by(id=user.groupe).first()
    assets_number = m.Asset.query.count()
    dict_list_sub = {}
    dict_list_sub['name'] = client.name

    if client.subscription:
        sub = m.Subscription.query.filter_by(id=client.subscription).first()
        dict_list_sub['Date_de_debut'] = dti.datetime.strftime((sub.start_at), '%d %B %Y')
        dict_list_sub['Date_de_fin'] = dti.datetime.strftime((sub.expire_on), '%d %B %Y')
        dict_list_sub['ID'] = sub.id
        dict_list_sub['Status'] = sub.status
        abon = m.Subs_plan.query.filter_by(id=sub.type).first()
        dict_list_sub['user_credits'] = abon.user_credits
        dict_list_sub['asset_credits'] = abon.asset_credits
        if abon:
            dict_list_sub['Type'] = abon.name
        else:
            dict_list_sub['Type'] = 'Unknown'
        dict_list_sub['assets_number'] = assets_number

    return jsonify(dict_list_sub)




# profile_detail_api_get ad_user
@app.route("/profile-detail-get-api", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def profile_detail_get_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    assets = m.Asset.query.filter_by(manager=current_user_id).all()
    role = user.role
    nb_assets = len(assets)
    return jsonify({"username": user.username, "role": role, "ass": nb_assets})


# Affichage nombre d'actifs
@app.route("/nombre-actif", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
# @jwt_required()
def nombre_actif_api():
    #   current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=13).first_or_404()
    assets = m.Asset.query.filter_by(manager=13).all()
    tickets = user.get_tickets()
    return jsonify({"count_assets": len(assets), "count_tickets": len(tickets)})


"""service-add api"""


@app.route('/service-api/add', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
# @login_required
# @requires_roles('ad_user')
def add_service_api():
    current_user_id = get_jwt_identity()
    # if not current_user.is_anonymous:
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    name = request.json.get('name')
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    services = client_group.get_services()
    expectedResult = [d for d in services if d['name'].lower() == name.lower() and len(d['name']) > 0]
    print('expected result', expectedResult)
    if len(expectedResult) > 0:
        return jsonify({"error": "Service existe d�ja"}), 400

    localisation = request.json.get('localisation')
    description = request.json.get('description')
    responsable = request.json.get('collab')
    user_collab = m.User.query.filter_by(username=responsable).first_or_404()
    service = m.Service(name=name, manager=current_user_id, responsable=user_collab.id)
    if localisation:
        service.localisation = localisation
    if description:
        service.description = description
    db.session.add(service)
    db.session.commit()
    flash('Service ajout� avec succ�s!')
    return jsonify({"success": "Service ajout� avec succ�s"}), 201


@app.route('/user/passwordapi', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def change_password_api():
    """ Modify user password """
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first()

    if user:
        old_password = request.json.get('old_password')
        new_password = request.json.get('password1')
        new_password2 = request.json.get('password2')
        print('oldpassword', old_password)
        print('newpassword', new_password)
        print('new_password_2', new_password2)
        if new_password2 != new_password:
            return jsonify({'msg': 'Password does not match ! '}), 400
        if not user.check_password(old_password):
            return jsonify({'msgasset/add-product-api': "ancien password n'est pas correct "}), 400
        else:

            user.set_password(new_password)
            db.session.commit()
            return jsonify({'msg': 'success'}), 200
    else:
        return jsonify({"Page introuvable!"}), 400


""" Show assets details"""


@app.route('/asset-detail-api/<asset_ref>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def asset_detail(asset_ref):
    current_user_id = get_jwt_identity()
    l1 = []
    user = m.User.query.filter_by(id=current_user_id).first()
    if user.role == "s_user":
        return jsonify("chaine vide"), 403
    all_assets = user.get_client_assets()
    for element in all_assets:
        if element['asset_ref'] == asset_ref:
            if (element['cpe']):
                cpe = m.Client_cpe.query.filter_by(id_cpe=element['cpe']).first_or_404()
                # element['cpe_readable'] = cpe.get_full_product_name()
                element['cpe_readable'] = cpe.name
                l1.append(element)
    return jsonify(l1)


@app.route('/asset-detail_v2-api/<asset_ref>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def asset_detail_api_v2(asset_ref):
    current_user_id = get_jwt_identity()
    l1 = []
    user = m.User.query.filter_by(id=current_user_id).first()
    all_assets = user.get_client_assets()
    asset_dict = {}
    list_ass = []
    list_ass.append(asset_ref)
    expectedResult = [d for d in all_assets if d['asset_ref'] in list_ass]

    if (len(expectedResult) > 0):
        asset = m.Asset.query.filter_by(asset_ref=asset_ref).first()

        service = m.Service.query.filter_by(id=asset.service).first()

        user_collab = m.User.query.filter_by(id=asset.responsable).first()
        name = 'None'
        if asset.importance == 1:
            importance = 'Mineur'
        elif asset.importance == 2:
            importance = 'Important'
        elif asset.importance == 3:
            importance = 'Majeur'
        else:
            importance = 'Critique'
        if user_collab:
            name = user_collab.username

        return ({'service': service.name, 'importance': importance, 'collaborateur': name})

    return jsonify({"chaine vide": 'vide'})


""" search assets with filter api"""


@app.route('/asset-api/search', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def search_assets_api():
    """ Show the result o the search (assets) """
    assets = None
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    asset_ref = request.json.get('asset_ref')
    manager = request.json.get('manager')
    service = request.json.get('service')
    status = request.json.get('status')
    assets = user.get_client_assets(asset_ref=asset_ref, manager=manager, service=service, status=status)
    status_str = {0: 'Activ�', 1: 'D�sactiv�'}  # Show the status of the asset as a string (Activ�/D�sactiv�)
    if len(assets) == 0:
        return jsonify({'msg': 'aucun asset trouv�'})
    else:
        return jsonify(assets), 201


""" Add new  Asset by Admin  """


@app.route('/asset/add', methods=['GET', 'POST'])
@login_required
@requires_roles('ad_user')
def add_asset():
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        form = f.AssetForm()
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        # form.manager.choices = [(u.id,u.username) for u in client_group.users]
        services = client_group.get_services()
        form.service.choices = [(s['id'], s['name']) for s in services]
        if form.validate_on_submit():
            asset = m.Asset(asset_ref=form.asset_ref.data, importance=form.importance.data, service=form.service.data)
            asset.owner = client_group
            db.session.add(asset)
            db.session.commit()
            """ Save logs """
            msg = f""" {current_user.username} added an asset ({asset.asset_ref})"""
            debug_log('info', msg)
            flash('Acif ajout� avec succ�s!')
            return redirect(url_for('add_asset'))
    return render_template('asset/add-asset.html', title='Nouveau client', form=form)


@app.route('/asset-api/add', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def add_asset_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    assets = user.get_client_assets()
    asset_ref = request.json.get('asset_ref')
    client = m.Client_group.query.filter_by(id=user.groupe).first()
    asset_id = get_asset_id(asset_ref=asset_ref, groupe_id=client.id)
    if asset_id:
        return jsonify("asset existe d�j�"), 400
    else:
        importance = request.json.get('importance')
        service = request.json.get('service')

        current_user_id = get_jwt_identity()
        s = []
        s.append(service)
        current_user_id = get_jwt_identity()
        user = m.User.query.filter_by(id=current_user_id).first_or_404()
        if user.role == "s_user":
            return jsonify("chaine vide"), 403
        else:
            client_group = m.Client_group.query.filter_by(id=user.groupe).first()
            services = client_group.get_services()
            expectedResult = [d for d in services if d['name'] in s]
            asset = m.Asset(asset_ref=asset_ref, importance=importance,
                            service=expectedResult[0]['id'], responsable=expectedResult[0]['responsable'])
            asset.owner = client_group
            asset.manager = current_user_id
            db.session.add(asset)
            db.session.commit()
            return jsonify({'asset': "success"}), 201


'''add product by s_user'''


@app.route('/asset/add-product-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def add_product_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client = m.Client_group.query.filter_by(id=user.groupe).first_or_404()
    client_info = client.get_all_info()
    assets_ref = user.get_assets_ref()
    special_characters = "!@#$%^&*()+?=,<>/"

    if int(client_info['cpe_credits']) <= int(client_info['nb_products']):  # all cpe credits are used
        flash(f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistr�s""")
        flash('Vous avez atteint la limite autoris�e de votre abonnement')
        print("Vous avez atteint la limite autoris�e de votre abonnement")
        return jsonify({'error': "Vous avez atteint la limite autoris�e de votre abonnement"}), 400
    else:
        cpe = m.Client_cpe()
        type = request.json.get('type')
        producer = request.json.get('producer')
        type = "a"
        if type == "os":
            type = "o"

        if any(c in special_characters for c in producer):
            print("le fournisseur ne peut pas contenir de caract�res sp�ciaux")
            return jsonify({'error': "le fournisseur ne peut pas contenir de caract�res sp�ciaux"}), 201

        producer = normalise_cpe_name(producer)
        name = request.json.get('name')
        if any(c in special_characters for c in name):
            print("le nom ne peut pas contenir de caract�res sp�ciaux")
            return jsonify({'error': "le nom ne peut pas contenir de caract�res sp�ciaux"}), 201
        name = normalise_cpe_name(name)
        asset_ref = request.json.get('asset_ref')
        if request.json.get('version'):
            version = normalise_cpe_name(request.json.get('version'))
        else:
            version = '*'
        cpe.set_cpe(type=type, producer=producer, name=name, version=version)
        asset = m.Asset.query.filter_by(groupe=user.groupe, asset_ref=asset_ref).first()
        a_u = m.Asset_usage.query.filter_by(cpe=cpe.id_cpe, asset_id=asset.id).first()
        if not a_u:
            """ Adding the asset_usage to the DB"""
            asset_usage = m.Asset_usage(asset_id=asset.id, cpe=cpe.id_cpe)  # creating asset_usage object
            client_cpe = m.Client_cpe.query.filter_by(id_cpe=cpe.id_cpe).first()  # creating client_cpe object
            if not client_cpe:  # the ne CPE already exists in the DB (client_cpe table)
                client_cpe = cpe
                db.session.add(client_cpe)
            asset_usage.cpes_usage = client_cpe
            # client_group.assets.append(asset_usage)
            # db.session.add(client_group)
            db.session.add(asset_usage)
            db.session.commit()
            return jsonify({'success': "Produit Cr�e avec succ�s"}), 201

        else:
            return jsonify({'error': "Produit existe d�j�"}), 400


'''remove product by s_user'''


@app.route('/asset/remove-product-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def delete_product_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    asset_ref = request.json.get('asset_ref')
    cpe_id = request.json.get('id')
    print('cpe_id', cpe_id, asset_ref)
    asset = m.Asset.query.filter_by(groupe=user.groupe, asset_ref=asset_ref).first()
    a_u = m.Asset_usage.query.filter_by(asset_id=asset.id, cpe=cpe_id).first()
    print('a_u', a_u)
    if not a_u:
        """ Adding the asset_usage to the DB"""
        return jsonify({'error': "Produit Introuvable"}), 201
    else:
        db.session.delete(a_u)
        db.session.commit()
        return jsonify({'success': "Suppression effectu�e avec succ�s"}), 201


""" import a list of assets  """


@app.route('/asset/import', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_ad')
def import_assets():
    if not current_user.is_anonymous:
        user = m.Analyst.query.filter_by(username=current_user.username).first_or_404()
        req = request
        form = f.UploadForm()
        if request.method == 'POST':
            if form.file.data:
                filename = secure_filename(form.file.data.filename)
                file_extension = pathlib.Path(filename).suffix
                if file_extension not in app.config['ALLOWED_EXTENSIONS']:
                    flash('Format de fichier non support�!')
                else:
                    file_data = request.files[form.file.name]
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file_data.save(file_path)
                    """ getting clients info (products credit information)"""
                    uu = m.User.query.filter_by(username="zgh").first_or_404()
                    client = m.Client_group.query.filter_by(id=uu.groupe).first()
                    client_info = client.get_all_info()
                    cpe_credits = int(client_info['cpe_credits']) - int(
                        client_info['nb_products'])  # calculate remaining cpe credits
                    """ Importing new assets"""
                    import_results = client.import_assets(file_path, cpe_credits)  # remaining product credits
                    print("manager", import_results['managers'][0])
                    """ Showing import results"""
                    flash(f'''{import_results['nb_assets']}  acifs ont �t� trouv� dans le fichier''')
                    flash(f'''{import_results['assets']} nouveaux acifs ont �t� ajout�s!''')
                    flash(f'''{import_results['nb_cpes']} produits ont �t� trouv�s dans le fichier!''')
                    flash(f'''{import_results['cpes']} nouveaux produits ont �t� ajout�s!''')
                    if import_results['nb_cpes'] != import_results['cpes']:
                        flash(f'''{import_results['duplicated_cpes']} produits sont dupliqu�s!''')
                    if import_results['cpe_credits'] == 0:
                        flash(f'''Vous avez atteint la limite de produits � ajouter''')
                    client_info = client.get_all_info()  # Getting product credits information after the import
                    flash(
                        f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistr�s""")
                    """ Save logs"""
                    msg = f""" {current_user.username} imported assets/products"""
                    debug_log('info', msg)

    return render_template('asset/import-assets.html', title='Actifs', form=form)


from flask import send_file


@app.route('/asset-api/delete', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def del_asset_api():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    asset_ref = request.json.get('asset_ref')
    asset = m.Asset.query.filter_by(asset_ref=asset_ref, groupe=client_group.id).first()
    db.session.delete(asset)
    db.session.commit()
    return jsonify({"msg": "success"})


@app.route('/asset/add-product', methods=['GET', 'POST'])
@login_required
# @requires_roles('ad_user')
def add_product():
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        client = m.Client_group.query.filter_by(id=user.groupe).first_or_404()
        client_info = client.get_all_info()
        assets_ref = user.get_assets_ref()
        form = f.ProductForm()
        form.asset_ref.choices = [(g['asset_ref']) for g in assets_ref]
        if form.validate_on_submit():
            if int(client_info['cpe_credits']) <= int(client_info['nb_products']):  # all cpe credits are used
                flash(f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistr�""")
                flash('Vous avez atteint la limite autoris� de votre abonnement')
            else:
                cpe = m.Client_cpe()
                type = form.type.data
                producer = normalise_cpe_name(form.producer.data)
                name = normalise_cpe_name(form.name.data)
                if form.version.data:
                    version = normalise_cpe_name(form.version.data)
                else:
                    version = '*'
                cpe.set_cpe(type=type, producer=producer, name=name, version=version)
                asset = m.Asset.query.filter_by(groupe=user.groupe, asset_ref=form.asset_ref.data).first()
                a_u = m.Asset_usage.query.filter_by(cpe=cpe.id_cpe, asset_id=asset.id).first()
                if not a_u:
                    """ Adding the asset_usage to the DB"""
                    asset_usage = m.Asset_usage(asset_id=asset.id, cpe=cpe.id_cpe)  # creating asset_usage object
                    client_cpe = m.Client_cpe.query.filter_by(id_cpe=cpe.id_cpe).first()  # creating client_cpe object
                    if not client_cpe:  # the ne CPE already exists in the DB (client_cpe table)
                        client_cpe = cpe
                        db.session.add(client_cpe)
                    asset_usage.cpes_usage = client_cpe
                    # client_group.assets.append(asset_usage)
                    # db.session.add(client_group)
                    db.session.add(asset_usage)
                    db.session.commit()
                    flash('Profuit ajout� avec succ�s!')
                    """ Save logs """
                    msg = f""" {current_user.username} added new product to {asset.asset_ref}"""
                    debug_log('info', msg)
                    return redirect(url_for('add_product'))
                else:
                    flash('Ce profuit existe d�j� dans l\'actif!')

    return render_template('asset/product_zak.html', title='Nouveau client', form=form)


""" Remove CPE from Asset by s_user"""


@app.route('/asset/del-product', methods=['GET', 'POST'])
@login_required
# @requires_roles('ad_user')
def del_product():
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        assets_ref = user.get_assets_ref()
        form = f.DelProductForm()
        form.asset_ref.choices = [(g['asset_ref']) for g in assets_ref]
        if form.validate_on_submit():
            cpe = m.Client_cpe()
            type = form.type.data
            producer = normalise_cpe_name(form.producer.data)
            name = normalise_cpe_name(form.name.data)
            if form.version.data:
                version = normalise_cpe_name(form.version.data)
            else:
                version = '*'
            cpe.set_cpe(type=type, producer=producer, name=name, version=version)
            asset = m.Asset.query.filter_by(groupe=user.groupe, asset_ref=form.asset_ref.data).first()
            a_u = m.Asset_usage.query.filter_by(cpe=cpe.id_cpe, asset_id=asset.id).first()
            if not a_u:
                """ Adding the asset_usage to the DB"""
                flash('Profuit introuvable! Veillez v�rifier votre saisie')
                return redirect(url_for('del_product'))
            else:
                db.session.delete(a_u)
                db.session.commit()
                flash('Produit Supprim� de l\'actif ', form.asset_ref.data)
                """ Save logs """
                msg = f""" {current_user.username} removed product from {asset.asset_ref}"""
                debug_log('info', msg)

    return render_template('asset/del_product.html', title='Suppression', form=form)


""" Ticket  management """
""" List tickets for user """


@app.route('/ticket/list')
@login_required
@requires_roles('s_user', 'ad_user')
def tickets():
    """ Show all tickets assigned to the client (user) """
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        tickets = user.get_tickets()
        for t in tickets:
            cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
            if cpe:
                t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
                # convert status int to string status readble by the user
                if t['status'] == -1:
                    t['status'] = 'Ferm�'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Trait�'
        search = False
        q = request.args.get('q')
        if q:
            search = True
        page = request.args.get(get_page_parameter(), type=int, default=1)
        pagination = Pagination(page=page, per_page=4, total=len(tickets), search=search, record_name='tickets')
        i = (page - 1) * 4
        tickets_1 = tickets[i:i + 4]
    return render_template('ticket/tickets.html', title='Tickets', tickets=tickets_1, pagination=pagination)


""" Show tickets information for Admin"""


@app.route('/ticket/list-all')
@login_required
@requires_roles('ad_user')
def ad_tickets():
    """ Show all tickets of the users for admin """
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        tickets = user.get_all_tickets()
        for t in tickets:  # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Ferm�'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'Pris en compte'
            elif t['status'] == 2:
                t['status'] = 'Trait�'
    return render_template('ticket/ad-tickets.html', title='Tickets', tickets=tickets)


""" Search tickets with filter """


@app.route('/ticket/search', methods=['GET', 'POST'])
@login_required
@requires_roles('ad_user', 's_user')
def search_tickets():
    """ Show the result o the search (tickets) """
    tickets = None
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        form = f.SearchTicketForm()
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        manager_choices = [(None, '')]
        for u in client_group.users:
            manager_choices.append((u.id, u.username))
        form.manager.choices = manager_choices
        if request.method == 'POST':
            # if form.validate_on_submit():
            if user.role == 'ad_user':
                tickets = user.get_all_tickets(cve=form.cve.data, manager=form.manager.data, score=form.score.data,
                                               status=form.status.data, opened_at_sup=form.after_o_date.data,
                                               opened_at_inf=form.before_o_date.data,
                                               closed_at_sup=form.after_f_date.data,
                                               closed_at_inf=form.before_f_date.data,
                                               sort_by=form.sort.data, direction=form.direction.data)
            else:  # the user is not an admin ==> list only the user tickets
                tickets = user.get_own_tickets(cve=form.cve.data, manager=form.manager.data, score=form.score.data,
                                               status=form.status.data, opened_at_sup=form.after_o_date.data,
                                               opened_at_inf=form.before_o_date.data,
                                               closed_at_sup=form.after_f_date.data,
                                               closed_at_inf=form.before_f_date.data,
                                               sort_by=form.sort.data, direction=form.direction.data)
            for t in tickets:  # convert status int to string status readble by the user
                if t['status'] == -1:
                    t['status'] = 'Ferm�'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Trait�'
            if len(tickets) == 0:
                flash('Aucun ticket n\'a �t� trouv�!')
                return redirect(url_for('search_tickets'))
            return render_template('ticket/search-ticket.html', title='Tickets', tickets=tickets, form=form)
    return render_template('ticket/search-ticket.html', title='Tickets', tickets=tickets, form=form)


""" Modify ticket """


@app.route('/ticket/<ticket_id>', methods=['GET', 'POST'])
@login_required
# @owner_required
@requires_roles('s_user')
def modify_ticket(ticket_id):
    """ Modify ticket status, Add comment, Add action to do """
    ticket = None
    form = f.ModifyTicketForm()
    if not current_user.is_anonymous:
        ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
        t = ticket.get_ticket(current_user.id)
        if t:
            cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
            if cpe:
                t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
                # convert status int to string status readble by the user
                if t['status'] == -1:
                    t['status'] = 'Ferm�'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Trait�'
            # if request.method == 'POST':
            if form.validate_on_submit():
                status = form.status.data
                ticket.status = status
                if not ticket.opened_at and status == '1':
                    now = datetime.now()
                    ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
                elif status == '-1':
                    now = datetime.now()
                    ticket.closed_at = now.strftime("%Y-%m-%d %H:%M:%S")
                ticket.action = form.action.data
                ticket.comment = form.comment.data
                db.session.commit()
                flash('Ticket modifi� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} modified ticket {ticket.id}"""
                debug_log('info', msg)
                # return redirect(url_for('modify_ticket', ticket_id=ticket_id)) # redirect to the same modify-ticket page
                return redirect(url_for('tickets'))  # redirect to the tickets page
        else:
            return "Page introuvable!"
    return render_template('ticket/modify-ticket.html', title='Tickets', ticket=t, form=form)


""" Ticket  management """
""" List tickets for user """


@app.route('/ticket-detail/<ticket_id>', methods=['GET'])
@login_required
@requires_roles('s_user', 'ad_user')
def ticket_detail(ticket_id):
    if not current_user.is_anonymous:
        ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
        t = ticket.get_ticket(current_user.id)
        if t:
            cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
            if cpe:
                t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
                # convert status int to string status readble by the user
                if t['status'] == -1:
                    t['status'] = 'Ferm�'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Trait�'

    return render_template('ticket/ticket_detail.html', title='Tickets', ticket=t)


@app.route('/ticket-detail-collab-api/<ticket_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
# @login_required
# @requires_roles('s_user', 'ad_user')
def collab_ticket_detail_api(ticket_id):
    #  if not current_user.is_anonymous:

    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_collab_ticket(user.id)

    if t:
        cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
        if cpe:
            t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
            # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Ferm�'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Trait�'
        return jsonify(t)
    return jsonify({"empty": "empty return"})


@app.route('/ticket-detail-api/<ticket_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
# @login_required
# @requires_roles('s_user', 'ad_user')
def ticket_detail_api(ticket_id):
    #  if not current_user.is_anonymous:

    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_ticket(user.id)
    print('t', t)

    if t:
        cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
        if cpe:
            t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
            # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Ferm�'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Trait�'
        return jsonify(t)
    return jsonify({"empty": "empty return"})


""" Authentification """


@app.route('/service-detail-api/<service_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
# @login_required
# @requires_roles('s_user', 'ad_user')
def service_detail_api(service_id):
    #  if not current_user.is_anonymous:

    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    service = m.Service.query.filter_by(id=service_id).first_or_404()
    print("service", service)
    print("user", user.id)
    print("service manager", service.manager)
    if user.id == service.manager:
        return jsonify(
            {
                "id": service.id, "localisation": service.localisation, "description": service.description,
                "name": service.name

            })
    else:
        return jsonify({"empty": "empty return"})


@app.route('/login', methods=['GET', 'POST'])  # accept both GET and Post request
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = f.LoginForm(request.form)
    if form.validate_on_submit():
        user = m.User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):  # status = 1 : user account is activated
            flash('Nom d\'utilisateur ou mot de passe invalide!')
            return redirect(url_for('login'))
        elif user.status != 1:
            flash('Votre compte n\'est pas activ�!')
            return redirect(url_for('login'))
        else:
            # login_user(user, remember=form.remember_me.data)
            # next_page = request.args.get('next')
            # if not next_page or url_parse(next_page).netloc != '':
            #  next_page = url_for('index')

            # msg = ''
            # debug_log('info', msg)
            login_user(user, remember=form.remember_me.data)
            next_page = url_for('token_second_fa')

            return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/login-cert', methods=['GET', 'POST'])  # accept both GET and Post request
def login_cert():
    """ Login CERT analyst to the application user """

    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = f.LoginForm(request.form)
    if form.validate_on_submit():
        analyst = m.Analyst.query.filter_by(username=form.username.data).first()
        if analyst is None or not analyst.check_password(
                form.password.data):  # status = 1 : analyst account is activated
            flash('Nom d\'utilisateur ou mot de passe invalide!')
            print('identifiants invalides')
            return redirect(url_for('login_cert'))
        elif analyst.status != 1:
            flash('Votre compte n\'est pas activ�!')
            return redirect(url_for('login_cert'))
        else:
            print('analyst', analyst)
            print('form', form.username.data)
            login_user(analyst, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            """ Save logs """
            msg = f""" {current_user.username} logged in to the platform"""
            print('msg', msg)
            debug_log('info', msg)
            print('current user', current_user.username)
            return redirect(next_page)

    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    username = current_user.username
    role = current_user.role
    logout_user()
    flash("Vous �tes maintenant d�connect�!", 'info')
    """ Save logs """
    msg = f""" {username} logged out"""
    debug_log('info', msg)
    if role in ['cert_user', 'cert_ad']:
        return redirect(url_for('login_cert'))
    else:
        return redirect(url_for('login_cert'))


""" Add a new user """


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """ Add new user to the database """
    # if current_user.is_authenticated:
    #     return redirect(url_for('index'))
    form = f.RegistrationForm()
    print('current_user', current_user)
    if form.validate_on_submit():
        user = m.User(username=form.username.data, nom=form.nom.data, prenom=form.prenom.data, email=form.email.data,
                      country_code=form.country_code.data,
                      phone=form.phone_number.data, groupe=form.groupe.data, role=form.role.data, status=1)
        user.set_password(form.password.data)
        secret = pyotp.random_base32()
        user.secret_2fa = secret
        db.session.add(user)
        db.session.commit()
        flash('Utilisateur ajout� avec succ�s!')
        """ Save logs """
        msg = f""" {current_user.username} added new user ({user.username})"""
        debug_log('info', msg)
        return redirect(url_for('register'))
    return render_template('register.html', title='Register', form=form)


""" Client administration """
""" Show user profile """


@app.route('/profile')  # flask will invoke the route function with the text between <> as argument
@login_required
def user():
    """ User profile"""
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(id=current_user.id).first_or_404()
        if user:
            assets = user.get_assets()
            roles = {'s_user': 'Utilisateur',
                     'ad_user': 'Admin'}  # Show the status of the asset as a string (Activ�/D�sactiv�)
            nb_assets = len(assets)
        else:
            nb_assets = 0
    return render_template('user.html', user=user, nb_assets=nb_assets, roles=roles)


""" Modify user password """


@app.route('/user/password/', methods=['GET', 'POST'])
@login_required
def change_password():
    """ Modify user password """
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(id=current_user.id).first()
        if user:
            form = f.ChangePasswordForm()
            if form.validate_on_submit():
                user.set_password(form.new_password.data)
                db.session.commit()
                flash('Mot de passe modifi� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} modified his password"""
                debug_log('info', msg)
                return redirect(url_for('user'))
        else:
            return "Page introuvable!"
    return render_template('user/change-password.html', title='Change Password', form=form, user=user)


""" CERT administration """
""" list all clients api"""

""" List all clients """


@app.route('/client-api/list')
def list_clients_api():
    """ list all clients """
    clients = get_clients_info()
    return jsonify(clients)


@app.route('/client/list')
@login_required
@requires_roles('cert_user', 'cert_ad')
def list_clients():
    """ list all clients """
    if not current_user.is_anonymous:
        clients = get_clients_info()
        status = {2: 'Expir�', 1: 'Activ�', 0: 'D�sactiv�'}
    print('current_user', current_user)
    return render_template('/client/list-clients.html', title='Clients', clients=clients, status=status)


""" add company api """


@app.route('/client-api/add', methods=['POST'])
def add_company_api():
    enterprise = request.json.get('entreprise')
    description = request.json.get('description')
    alert = request.json.get('alert')
    client_group = m.Client_group(name=enterprise, type=description, alerts=alert)
    db.session.add(client_group)
    db.session.commit()

    return jsonify({"msg": "company added successfully"})


""" Add a client """


@app.route('/client/add', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def add_company():
    if not current_user.is_anonymous:
        form = f.CompanyForm()
        if form.validate_on_submit():
            client_group = m.Client_group(name=form.name.data, type=form.type.data, alerts=form.alerts.data)
            db.session.add(client_group)
            db.session.commit()
            flash('Client ajout� avec succ�s!')
            """ Save logs """
            msg = f""" {current_user.username} added new client ({client_group.name})"""
            debug_log('info', msg)
            return redirect(url_for('login'))
    return render_template('client/company.html', title='Nouveau client', form=form)


""" Remove client"""


@app.route('/client/remove', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def del_company():
    if not current_user.is_anonymous:
        form = f.DeleteCompanyForm()
        clients = get_clients()
        form.name.choices = [(c['id'], c['name']) for c in clients]
        if form.validate_on_submit():
            client = m.Client_group.query.filter_by(id=form.name.data).first()
            db.session.delete(client)
            db.session.commit()
            flash('Clientf Supprim� avec succ�s!')
            """ Save logs """
            msg = f""" {current_user.username} removed client ({client.name})"""
            debug_log('info', msg)
            return redirect(url_for('del_company'))
    return render_template('client/del-client.html', title='Suppression', form=form)


""" Modify client """


@app.route('/client/<client_name>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def modify_company(client_name):
    if not current_user.is_anonymous:
        client = m.Client_group.query.filter_by(name=client_name).first()
        client_info = client.get_all_info()
        if client:
            form = f.ModifyCompanyForm()
            form.name.default = client_name
            alerts_str = {1: 'Activ�', 0: 'D�sactiv�'}
            if form.validate_on_submit():
                if form.name.data:
                    client.name = form.name.data
                if form.type.data:
                    client.type = form.type.data
                if form.alerts.data:
                    client.alerts = form.alerts.data
                db.session.commit()
                flash('Client modifi� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} modified client information ({client.name})"""
                debug_log('info', msg)
                return redirect(url_for('modify_company', client_name=client.name))
        else:
            return "Page introuvable!"
    return render_template('client/modify-company.html', title='Modifier client', form=form, client=client_info,
                           alerted=alerts_str)


""" List analysts """


@app.route('/analyst/list')
@login_required
@requires_roles('cert_ad')
def list_analysts():
    """ Show all analysts for the cert admin """
    if not current_user.is_anonymous:
        analysts = get_analysts()
        status_str = {1: 'Activ�', 0: 'D�sactiv�',
                      -1: 'Supprim�'}  # Show the status of the user as a string (Activ�/D�sactiv�/Supprim�)
    return render_template('analyst/list-analysts.html', title='Analysts', analysts=analysts, status=status_str)


""" Add a new analyst """


@app.route('/analyst/add', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_ad')
def add_analyst():
    """ Add new analyst to the database """
    # if current_user.is_authenticated:
    #     return redirect(url_for('index'))
    form = f.AnalystForm()
    if form.validate_on_submit():
        analyst = m.Analyst(username=form.username.data, email=form.email.data, country_code=form.country_code.data,
                            phone=form.phone_number.data, role=form.role.data, status=1)
        analyst.set_password(form.password.data)
        db.session.add(analyst)
        db.session.commit()
        flash('Analyste ajout� avec succ�s!')
        """ Save logs """
        msg = f""" {current_user.username} added new user ({analyst.username})"""
        debug_log('info', msg)
        return redirect(url_for('list_analysts'))
    return render_template('analyst/add-analyst.html', title='New Analyst', form=form)


""" List pretickets for analyst """


@app.route('/analyst/tickets')
@login_required
@requires_roles('cert_user')
def analyst_tickets():
    """ Show all tickets assigned to the analyst """
    if not current_user.is_anonymous:
        analyst = m.Analyst.query.filter_by(username=current_user.username).first_or_404()
        tickets = analyst.get_tickets()
        for t in tickets:
            cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
            if cpe:
                t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
                # convert status int to string status readble by the user
                if t['status'] == 3:
                    t['status'] = 'Annul�'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Valid�'
    return render_template('analyst/list-tickets.html', title='Analyst Tickets', tickets=tickets)


"""analyze directly"""


def analyze_ticket_directly(current_user):
    """ Modify ticket status, Add comment, Add action to do """
    pre_tickets = m.Pre_ticket.query.all()
    for t in pre_tickets:
        # create ticket
        asset_usage_instance = m.Asset_usage.query.filter_by(id=t.usage_id).first_or_404()
        asset = m.Asset.query.filter_by(id=asset_usage_instance.asset_id).first_or_404()
        ticket = m.Ticket(usage_id=t.usage_id, cve=t.cve,
                          created_at=t.created_at, score=t.score,
                          pre_ticket=t.id,
                          manager=asset.manager
                          )
        t.ticket = ticket
        db.session.add(ticket)
        db.session.commit()


""" Analyze preticket """


@app.route('/analyst/ticket/<preticket_id>', methods=['GET', 'POST'])
@login_required
# @owner_required
@requires_roles('cert_user')
def analyze_ticket(preticket_id):
    """ Modify ticket status, Add comment, Add action to do """
    ticket = None
    form = f.AnalyzeTicketForm()
    if not current_user.is_anonymous:
        pre_ticket = m.Pre_ticket.query.filter_by(id=preticket_id).first_or_404()
        pt = pre_ticket.get_pre_ticket(current_user.id)
        if pt:
            cpe = m.Client_cpe.query.filter_by(id_cpe=pt['cpe']).first_or_404()
            if cpe:
                pt['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
                # convert status int to string status readble by the user
                if pt['status'] == 3:
                    pt['status'] = 'Annul�'
                elif pt['status'] == 0:
                    pt['status'] = 'En attente'
                elif pt['status'] == 1:
                    pt['status'] = 'En cours d\'analyse'
                elif pt['status'] == 2:
                    pt['status'] = 'Valid�'
            # if request.method == 'POST':
            if form.validate_on_submit():
                status = form.action.data
                now = datetime.now()
                # update pre_ticket info
                if form.recommendation.data:
                    pre_ticket.recommendation = form.recommendation.data
                if form.comment.data:
                    pre_ticket.comment = form.comment.data
                # set opened datetime
                if not pre_ticket.opened_at and status == '0':
                    pre_ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
                if status == '-1':  # ignore the ticket (not send to the client)
                    pre_ticket.status = 3
                    flash('ticket trait�!')
                elif status == '1':  # validate the ticket send it to the clients
                    now = datetime.now()
                    # set treated_at datetime
                    pre_ticket.treated_at = now.strftime("%Y-%m-%d %H:%M:%S")
                    pre_ticket.status = 2
                    # create ticket
                    ticket = m.Ticket(usage_id=pre_ticket.usage_id, cve=pre_ticket.cve,
                                      created_at=now.strftime("%Y-%m-%d %H:%M:%S"), score=pre_ticket.score,
                                      pre_ticket=pre_ticket.id)
                    pre_ticket.ticket = ticket
                    flash('ticket valid�!')
                else:
                    pre_ticket.status = 1
                db.session.commit()

                """ Save logs """
                msg = f""" {current_user.username} analyzed pre_ticket {pre_ticket.id}"""
                debug_log('info', msg)
                return redirect(url_for('analyze_ticket', preticket_id=preticket_id))
        else:
            return "Page introuvable!"
    return render_template('analyst/analyze-ticket.html', title='Tickets', ticket=pt, form=form)


""" List all users of a client """


@app.route('/client/<client_name>/users')
@login_required
@requires_roles('cert_user', 'cert_ad')
def list_client_users(client_name):
    """ Show all users of the client for the CERT analyst (or CERT manager) """
    if not current_user.is_anonymous:
        client_group = m.Client_group.query.filter_by(name=client_name).first()
        users = client_group.users
        status_str = {1: 'Activ�', 0: 'D�sactiv�',
                      -1: 'Supprim�'}  # Show the status of the user as a string (Activ�/D�sactiv�/Supprim�)
        roles = {'ad_user': 'Admin', 's_user': 'Analyste'}
    return render_template('client/list-client-users.html', title='Client Users', users=users, status=status_str,
                           roles=roles, client_name=client_name)


""" Modify client user information """


@app.route('/client/modify-user/<username>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def modify_user(username):
    """ Modify user information """
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=username).first()
        client = m.Client_group.query.filter_by(id=user.groupe).first()
        if user:
            form = f.ModifyUserForm()
            status_str = {1: 'Activ�', 0: 'D�sactiv�',
                          -1: 'Supprim�'}  # Show the status of the user as a string (Activ�/D�sactiv�/Supprim�)
            roles = {'ad_user': 'Admin', 's_user': 'Analyste'}
            if form.validate_on_submit():
                if form.username.data:
                    user.username = form.username.data
                if form.status.data:
                    user.status = int(form.status.data)
                if form.role.data:
                    user.role = form.role.data
                if form.country_code.data:
                    user.country_code = int(form.country_code.data)
                if form.phone_number.data:
                    user.phone_number = form.phone_number.data
                db.session.commit()
                flash('Utilisateur modifi� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} modified user information ({user.username})"""
                debug_log('info', msg)
                return redirect(url_for('list_client_users', client_name=client.name))
        else:
            return "Page introuvable!"
    return render_template('user/modify-user.html', title='Modifier client', form=form, user=user,
                           client_name=client.name, roles=roles, status=status_str)


""" delete user"""


@app.route('/<client_name>/user/remove', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def del_user(client_name):
    if not current_user.is_anonymous:
        form = f.DeleteUserForm()
        client_group = m.Client_group.query.filter_by(name=client_name).first()
        users = client_group.users
        form.id.choices = [(u.id, u.username) for u in users]
        if form.validate_on_submit():
            user = m.User.query.filter_by(id=form.id.data).first()
            db.session.delete(user)
            db.session.commit()
            flash(f"""Le compte de {user.username} a �t� supprim�!""")
            """ Save logs """
            msg = f""" {current_user.username} deleted user ({user.username})"""
            debug_log('info', msg)
            return redirect(url_for('list_client_users', client_name=client_name))
    return render_template('user/del-user.html', title='Suppression Utilisateur', form=form, client_name=client_name)


# """ Disable user"""
# @app.route('/<client_name>/user/disable', methods=['GET', 'POST'])
# @login_required
# @requires_roles('cert_user','cert_ad')
# def disable_user(client_name):
#     if not current_user.is_anonymous:
#         form = f.DisableUserForm()
#         client_group = m.Client_group.query.filter_by(name=client_name).first()
#         users = client_group.users
#         form.id.choices = [(u.id,u.username) for u in users]
#         if form.validate_on_submit():
#             user = m.User.query.filter_by(id=form.id.data).first()
#             user.status = 0
#             db.session.commit()
#             flash(f"""Le compte de {user.username} a �t� d�sactiv�!""")
#             return redirect(url_for('list_client_users', client_name=client_name))
#
#     return render_template('user/disable-user.html', title='Disable User', form=form,client_name=client_name)


""" List all subscriptions plan """


@app.route('/client/plan')
@login_required
@requires_roles('cert_user', 'cert_ad')
def list_plans():
    """ list all plans """
    if not current_user.is_anonymous:
        plans = m.Subs_plan.query.all()
    return render_template('/client/list-plan.html', title='Plans', plans=plans)


""" Add a subscription plan """


@app.route('/client/plan/add', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def add_plan():
    if not current_user.is_anonymous:
        form = f.PlanForm()
        if form.validate_on_submit():
            plan = m.Subs_plan(name=form.name.data, user_credits=form.user_credits.data,
                               cpe_credits=form.cpe_credits.data, payement=form.payement.data)
            db.session.add(plan)
            db.session.commit()
            flash('Plan d\'abonnement ajout� avec succ�s!')
            """ Save logs """
            msg = f""" {current_user.username} added suscription plan ({plan.name})"""
            debug_log('info', msg)
            return redirect(url_for('list_plans'))
    return render_template('client/add-plan.html', title='Nouveau Abonnement', form=form)


""" Modify subscription plan """


@app.route('/client/plan/<plan_name>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def modify_plan(plan_name):
    if not current_user.is_anonymous:
        plan = m.Subs_plan.query.filter_by(name=plan_name).first()
        if plan:
            form = f.ModifyPlanForm()
            if form.validate_on_submit():
                if form.name.data:
                    plan.name = form.name.data
                if form.user_credits.data:
                    plan.user_credits = form.user_credits.data
                if form.cpe_credits.data:
                    plan.cpe_credits = form.cpe_credits.data
                if form.payement.data:
                    plan.payement = form.payement.data
                db.session.commit()
                flash('Abonnement modifi� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} modified suscription plan informations ({plan.name})"""
                debug_log('info', msg)
                return redirect(url_for('list_plans', plan_name=plan.name))
        else:
            return "Page introuvable!"
    return render_template('client/modify-plan.html', title='Modifier Abonnement', form=form, plan=plan)


""" Remove subscription plan"""


@app.route('/client/paln/remove', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def del_plan():
    if not current_user.is_anonymous:
        form = f.DeletePlanForm()
        plans = m.Subs_plan.query.all()
        form.id.choices = [(p.id, p.name) for p in plans]
        if form.validate_on_submit():
            plan = m.Subs_plan.query.filter_by(id=form.id.data).first()
            db.session.delete(plan)
            db.session.commit()
            flash('Abonnement supprim� avec succ�s!')
            """ Save logs """
            msg = f""" {current_user.username} removed suscription plan ({plan.name})"""
            debug_log('info', msg)
            return redirect(url_for('list_plans'))
    return render_template('client/del-plan.html', title='Suppression', form=form)


""" Add subscription to a client """


@app.route('/client/subscription', methods=['GET', 'POST'])
@requires_roles('cert_user', 'cert_ad')
def add_subscription():
    if not current_user.is_anonymous:
        form = f.SubscriptionForm()
        clients = m.Client_group.query.filter_by(subscription=None).all()
        subs_plans = m.Subs_plan.query.all()
        form.client.choices = [(c.id, c.name) for c in clients]
        form.plan.choices = [(p.id, p.name) for p in subs_plans]
        if form.validate_on_submit():
            client = m.Client_group.query.filter_by(id=form.client.data).first()
            plan = m.Subs_plan.query.filter_by(id=form.plan.data).first()
            subscription = m.Subscription(type=form.plan.data, start_at=form.start_at.data,
                                          expire_on=form.expire_on.data)
            subscription.client = client
            # subscription.plan = plan
            db.session.add(subscription)
            # client.subs_obj = subscription
            db.session.commit()
            flash(f""" {client.name} est souscrit � l\'subscription{plan.name} avec succ�s!""")
            """ Save logs """
            msg = f""" {current_user.username} subscribed {client.name} to {plan.name}"""
            debug_log('info', msg)
            return redirect(url_for('list_clients'))
    return render_template('client/add-subscription.html', title='Souscription', form=form)


""" Change subscription"""


@app.route('/client/subscription/modify/<subs_id>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def modify_subscription(subs_id):
    if not current_user.is_anonymous:
        form = f.ModifySubsForm()
        subs_plans = m.Subs_plan.query.all()
        form.plan.choices = [(p.id, p.name) for p in subs_plans]
        subscription = m.Subscription.query.filter_by(id=subs_id).first()
        status = {2: 'Expir�', 1: 'Activ�', 0: 'D�sactiv�'}
        if form.validate_on_submit():
            # elif form.action.data == 'Changer':
            subscription.type = form.plan.data
            subscription.start_at = form.start_at.data
            subscription.expire_on = form.expire_on.data
            subscription.status = 1
            db.session.commit()
            flash('Abonnement modifi� avec succ�s!')
            """ Save logs """
            msg = f""" {current_user.username} changed subscription of {subscription.client.name}"""
            debug_log('info', msg)
            # elif form.action.data == 'D�sactiver': # put the status to 0 and expire_on to the expiry's day date
            #     subscription.status = 0
            #     now = datetime.now()
            #     subscription.expire_on = now.strftime("%Y-%m-%d %H:%M:%S")
            #     db.session.commit()
            #     flash('Abonnement d�sactiv� pour le client ',subscription.client.id)
            return redirect(url_for('list_clients'))
    return render_template('client/modify-subs.html', title='Suppression', form=form, subscription=subscription,
                           status=status)


""" Extend subscription"""


@app.route('/client/subscription/extend/<subs_id>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def extend_subscription(subs_id):
    if not current_user.is_anonymous:
        form = f.ExtendSubsForm()
        subscription = m.Subscription.query.filter_by(id=subs_id).first()
        status = {2: 'Expir�', 1: 'Activ�', 0: 'D�sactiv�'}
        if form.validate_on_submit():
            subscription.status = 1
            expire_date = datetime.combine(form.expire_on.data, datetime.min.time())
            if subscription.expire_on < expire_date:
                subscription.expire_on = expire_date
                db.session.commit()
                flash('Abonnement prolong� avec succ�s!')
                """ Save logs """
                msg = f""" {current_user.username} extended subscription of {subscription.client.name} to {subscription.expire_on}"""
                debug_log('info', msg)
                return redirect(url_for('list_clients'))
            else:
                flash('L\'Abonnement n\'a pas �t� prolong�!')
                flash('La nouvelle date d\'expiration est invalide')
                return redirect(url_for('extend_subscription', subs_id=subs_id))

    return render_template('client/extend-subs.html', title='Extend subscription', form=form, subscription=subscription,
                           status=status)


""" Disable/Cancel subscription"""


@app.route('/client/subscription/disable/<subs_id>', methods=['GET', 'POST'])
@login_required
@requires_roles('cert_user', 'cert_ad')
def disable_subscription(subs_id):
    if not current_user.is_anonymous:
        form = f.DisableSubsForm()
        subscription = m.Subscription.query.filter_by(id=subs_id).first()
        status = {2: 'Expir�', 1: 'Activ�', 0: 'D�sactiv�', -1: 'D�sactiv�'}
        if form.validate_on_submit():
            if form.action.data == 'disable':
                subscription.status = 0
                now = datetime.now()
                subscription.expire_on = now.strftime("%Y-%m-%d %H:%M:%S")
                db.session.commit()
                flash(f"""Abonnement d�sactiv� pour {subscription.client.name}""")
                """ Save logs """
                msg = f""" {current_user.username} disabled subscription of {subscription.client.name}"""
                debug_log('info', msg)
            elif form.action.data == 'cancel':
                db.session.delete(subscription)
                db.session.commit()
                flash(f"""Abonnement annul� pour {subscription.client.name}""")
                """ Save logs """
                msg = f""" {current_user.username} canceled subscription of {subscription.client.name}"""
                debug_log('info', msg)
            return redirect(url_for('list_clients'))

    return render_template('client/disable-subs.html', title='Extend subscription', form=form,
                           subscription=subscription, status=status)


""" Show subscription informations for client"""


@app.route('/subscription')
@login_required
@requires_roles('ad_user')
def subscription():
    """ list all clients """
    if not current_user.is_anonymous:
        user = m.User.query.filter_by(username=current_user.username).first_or_404()
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        subs_info = client_group.get_subscription_info()
        status = {2: 'Expir�', 1: 'Activ�', 0: 'D�sactiv�'}
    return render_template('subscription.html', title='Subscription', subs=subs_info, status=status)


""" 2FA authy functions """


@app.route('/login-authy', methods=['GET', 'POST'])  # accept both GET and Post request
def login_authy():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = f.LoginForm(request.form)
    if form.validate_on_submit():
        user = m.User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            session['user_id'] = user.id
            if user.has_authy_app:
                # Send a request to verify this user's login with OneTouch
                one_touch_response = user.send_one_touch_request()
                login_user(user, remember=form.remember_me.data)
                # redirect user to next page
                # next_page = request.args.get('next')
                # if not next_page or url_parse(next_page).netloc != '':
                #     next_page = url_for('index')
                # return jsonify(one_touch_response)
                return redirect(url_for('wait'))  # testing
            else:
                return jsonify({'success': False})
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    if request.method == 'POST':
        # This was an AJAX request, and we should return any errors as JSON
        print('methode post')
        return jsonify({'error': render_template('_login_error.html', form=form)})  # noqa: E501
    else:
        # return redirect(next_page)
        print('methode not post')
        return render_template('login.html', title='Sign In', form=form)


""" Sign-up with authy """


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    """Powers the new user form"""
    form = f.RegistrationForm(request.form)

    if form.validate_on_submit():
        try:
            user = create_user(form)
            session['user_id'] = user.id

            return redirect(url_for('login'))

        except AuthyApiException as e:
            form.errors['Authy API'] = ['There was an error creating the Authy user', e.msg, ]

    return render_template('signup.html', form=form)


""" Authy call back"""


@app.route('/authy/callback', methods=['POST'])
@verify_authy_request
def authy_callback():
    """Authy uses this endpoint to tell us the result of a OneTouch request"""
    authy_id = request.json.get('authy_id')
    # When you're configuring your Endpoint/URL under OneTouch settings '1234' is the preset 'authy_id'
    if authy_id != 1234:
        user = m.User.query.filter_by(authy_id=authy_id).one()
        print('user: ', user)
        if not user:
            return ('', 404)

        user.authy_status = request.json.get('status')
        db.session.add(user)
        db.session.commit()
    return ('', 200)
    # return redirect(url_for('index'))  # testing


@app.route('/wait')
def wait():
    """
    This function check if the user has approuved 2FA in the authy application
    """
    while True:
        authy_id = current_user.authy_id
        user = m.User.query.filter_by(authy_id=authy_id).one()
        # test_session = session
        # result = session.query(User).filter_by(authy_id=current_user.authy_id).one
        # status = session['user_id']
        # print(user)
        if user.authy_status == 'approved':
            flash('Autorisation confirm�!')
            return redirect(url_for('index'))
        elif user.authy_status == 'denied':
            flash('Autorisation refus�!')
            return redirect(url_for('login'))


@app.route('/login/status')
def login_status():
    """
    Used by AJAX requests to check the OneTouch verification status of a user
    """
    user = m.User.query.get(session['user_id'])
    return user.authy_status


@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    """Powers token validation (not using OneTouch)"""
    form = f.VerifyForm(request.form)
    user = m.User.query.get(session['user_id'])

    # Send a token to our user when they GET this page
    if request.method == 'GET':
        send_authy_token_request(user.authy_id)

    if form.validate_on_submit():
        user_entered_code = form.verification_code.data

        verified = verify_authy_token(user.authy_id, str(user_entered_code))
        if verified.ok():
            user.authy_status = 'approved'
            db.session.add(user)
            db.session.commit()

            flash(
                "You're logged in! Thanks for using two factor verification.", 'success'
            )  # noqa: E501
            return redirect(url_for('main.account'))
        else:
            form.errors['verification_code'] = ['Code invalid - please try again.']

    return render_template('verify.html', form=form)


@app.route('/resend', methods=['POST'])
@login_required
def resend():
    """Resends a verification token to a user"""
    user = m.User.query.get(session.get('user_id'))
    send_authy_token_request(user.authy_id)
    flash('I just re-sent your verification code - enter it below.', 'info')
    return redirect(url_for('auth.verify'))


@app.route('/logout-authy')
def logout_authy():
    user_id = session.pop('user_id', None)
    user = m.User.query.get(user_id)
    user.authy_status = 'unverified'
    db.session.add(user)
    db.session.commit()
    logout_user()
    flash("You're now logged out! Thanks for visiting.", 'info')
    return redirect(url_for('login'))


@app.route('/list-vuls_dash_team', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_vuls_team():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    tickets = user.get_user_tickets()
    ################# tickets criticity #################"
    liste_tickets_by_criticity = []
    liste_tickets_by_assets = []
    liste_tickets_table = []
    outputList2_criticity_x = []
    outputList2_criticity_y = []
    outputList2_assets_x = []
    outputList2_tickets_trend_x = []
    outputList2_tickets_trend_y = []
    count_en_attente = 0
    count_en_cours = 0
    count_traites = 0
    count_fermes = 0
    month_index = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    count_vuls = 0
    non_closed_tickets = []
    closed_tickets = []
    count_status_0 = 0
    count_status_1 = 0
    if len(tickets) > 0:
        list_cves_len = []
        tickets_2 = sorted(tickets, key=itemgetter('cve'))
        for n, k in groupby(tickets_2, key=itemgetter("cve")):
            list_cves_len.append(list(k))
        count_vuls = len(list_cves_len)
        closed_tickets = user.get_closed_tickets_team()
        non_closed_tickets = len(tickets) - len(closed_tickets)
        for element in tickets:

            dict_criticity = {}
            dict_criticity['id_ticket'] = element['id']
            if (element['score']):
                dict_criticity['score'] = round(element['score'])
            else:
                dict_criticity['score'] = 0
            liste_tickets_by_criticity.append(dict_criticity)

            dict_asset_top = {}
            dict_asset_top['id_ticket'] = element['id']
            dict_asset_top['asset_ref'] = element['asset_ref']
            liste_tickets_by_assets.append(dict_asset_top)

            if element['status'] == 0:
                count_en_attente = count_en_attente + 1
            elif element['status'] == 1:
                count_en_cours = count_en_cours + 1

            elif element['status'] == 2:
                count_traites = count_traites + 1
            else:
                count_fermes = count_fermes + 1

        liste_vuls_chart1 = sorted(liste_tickets_by_criticity, key=itemgetter('score'))
        outputList1_criticity = []

        for n, k in groupby(liste_vuls_chart1, key=itemgetter("score")):
            outputList1_criticity.append(list(k))
        for element in outputList1_criticity:
            for e in element:
                outputList2_criticity_x.append(e['score'])
                break
            taille = len(element)
            outputList2_criticity_y.append(taille)
        ################# tickets trend #################"
        liste_tickets_by_trend = []
        if len(tickets) > 0:
            for element in tickets:
                dict_tickets_trend = {}
                dict_tickets_trend['id_ticket'] = element['id']
                dict_tickets_trend['created_at'] = dti.datetime.strptime(element['created_at'],
                                                                              '%Y-%m-%d %H:%M:%S').month
                liste_tickets_by_trend.append(dict_tickets_trend)

            liste_vuls_chart2 = sorted(liste_tickets_by_trend, key=itemgetter('created_at'))
            outputList1_tickets_trend = []

            for n, k in groupby(liste_vuls_chart2, key=itemgetter("created_at")):
                outputList1_tickets_trend.append(list(k))
            for element in outputList1_tickets_trend:
                for e in element:
                    month_number = e['created_at']
                    datetime_object = dti.datetime.strptime(str(month_number), "%m")
                    month_name = datetime_object.strftime("%B")
                    outputList2_tickets_trend_x.append(month_name)
                    break
                taille = len(element)
                outputList2_tickets_trend_y.append(taille)

            for month in month_index:
                if month not in outputList2_tickets_trend_x:
                    outputList2_tickets_trend_x.insert(month_index.index(month), month)
                    outputList2_tickets_trend_y.insert(month_index.index(month), 0)

            liste_vuls_chart6 = sorted(liste_tickets_by_assets, key=itemgetter('asset_ref'))
            outputList1_tickets_assets = []
            outputList2_assets_x = []
            outputList2_assets_y = []

            for n, k in groupby(liste_vuls_chart6, key=itemgetter("asset_ref")):
                outputList1_tickets_assets.append(list(k))
            if len(outputList1_tickets_assets) > 5:
                outputList2_tickets_assets = outputList1_tickets_assets[
                                             len(outputList1_tickets_assets) - 3:len(outputList1_tickets_assets)]
            else:
                outputList2_tickets_assets = outputList1_tickets_assets

            for element in outputList2_tickets_assets:
                for e in element:
                    dict_assets_length = {}
                    dict_assets_length['asset_ref'] = e['asset_ref']
                    break
                taille = len(element)
                dict_assets_length['size'] = taille
                outputList2_assets_x.append(dict_assets_length)
            print("output asstes tickets", outputList2_assets_x)
        lky = outputList2_assets_x[0:2]
        assets = user.get_assets()
        count_status_0 = 0
        count_status_1 = 0
        for element in assets:
            if element['status'] == 0:
                count_status_0 = count_status_0 + 1
            else:
                count_status_1 = count_status_1 + 1
        closed_tickets = user.get_closed_tickets_team()

    vuls = m.Cve_temp.query.all()
    nb_vuls = len(vuls)
    outputList2_vuls_trend_y = []
    outputList2_vuls_trend_x = []
    outputList2_vuls_trend = []
    if nb_vuls > 0:
        for element in vuls:
            if element.published_at:
                dict_vuls_trend = {}
                dict_vuls_trend['id'] = element.id
                dict_vuls_trend['published_at'] = element.published_at.month
                outputList2_vuls_trend.append(dict_vuls_trend)
        liste_vuls_chart2_2 = sorted(outputList2_vuls_trend, key=itemgetter('published_at'))

        outputList1_vuls_trend = []

        for n, k in groupby(liste_vuls_chart2_2, key=itemgetter("published_at")):
            outputList1_vuls_trend.append(list(k))
        for element in outputList1_vuls_trend:
            for e in element:
                month_number = e['published_at']
                datetime_object = dti.datetime.strptime(str(month_number), "%m")
                month_name = datetime_object.strftime("%B")
                outputList2_vuls_trend_x.append(month_name)
                break
            taille = len(element)
            outputList2_vuls_trend_y.append(taille)
        for month in month_index:
            if month not in outputList2_vuls_trend_x:
                outputList2_vuls_trend_x.insert(month_index.index(month), month)
                outputList2_vuls_trend_y.insert(month_index.index(month), 0)
    assets = m.Asset.query.filter_by(responsable=user.id).all()
    nb_assets = len(assets)
    print('tickets_criticity_x', outputList2_criticity_x)
    print('tickets_criticity_y', outputList2_criticity_y)
    recent_tickets = []
    if tickets:
        tickets_2 = sorted(tickets, key=itemgetter('created_at'), reverse=False)
        if len(tickets_2) > 5:
            recent_tickets = tickets_2[0:5]
        else:
            recent_tickets = tickets_2
        print(recent_tickets)
    return jsonify({"tickets_criticity_x": outputList2_criticity_x, 'count_vuls': count_vuls, 'nb_assets': nb_assets,
                    'closed_tickets': len(closed_tickets), 'non_closed_tickets': non_closed_tickets,
                    "tickets_criticity_y": outputList2_criticity_y,
                    "outputList2_tickets_trend_x": outputList2_tickets_trend_x,
                    "outputList2_tickets_trend_y": outputList2_tickets_trend_y,
                    "outputList2_vuls_trend_y": outputList2_vuls_trend_y, 'tickets': recent_tickets,
                    'outputList2_assets_x': outputList2_assets_x,
                    "count_status_0": count_status_0, "count_status_1": count_status_1,
                    'count_en_attente': count_en_attente, 'count_en_cours': count_en_cours,
                    'count_traites': count_traites, 'count_fermes': count_fermes})


@app.route('/add-user-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def ad_user_admin_client():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    current_user_id = get_jwt_identity()
    username = request.json.get('username')
    prenom = request.json.get('surname')
    nom = request.json.get('name')
    email = request.json.get('email')
    country_code = request.json.get('country_code')
    phone = request.json.get('phone')
    role = request.json.get('role')
    role_value = ""
    if role == "Admin":
        role_value = "ad_user"
    else:
        role_value = "s_user"

    password = request.json.get('password')
    user = m.User(username=username, nom=nom, prenom=prenom, email=email,
                  country_code=country_code, phone=phone, groupe=client_group.id, role=role_value, status=1)
    user.set_password(password)
    secret = pyotp.random_base32()
    user.secret_2fa = secret
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'success'})





@app.route('/assign-ticket', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def assign_ticket_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == 'ad_user':
        due_date = request.json.get("dueDate")
        collaborateur = request.json.get("responsable")
        notifier = request.json.get("notifier")
        ticket_id = request.json.get('ticket_id')

        ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
        t = ticket.get_ticket(user.id)
        responsable = m.User.query.filter_by(username=collaborateur).first_or_404()

        if t:
            if responsable:
                ticket.responsable = responsable.id

                db.session.commit()

            else:
                return {
                    "message": "error"
                }, 404
            if due_date:
                ticket.due_date = due_date

                db.session.commit()
            if notifier:
                sender_email = 'pgv.brightway@gmail.com'
                receiver = responsable.email

                message = MIMEMultipart("alternative")
                subject = "[Brightwatch]Nouvelle affectation de tickets"
                message["Subject"] = subject
                message["From"] = sender_email
                message["To"] = receiver
                html = f"""\
                  <html>
                    <body>
                  <p>
                  Bonjour, 
                   <br>
                    <br>
                  Vous &ecirc;tes inscrit(e) au service Brightwatch.
                  <br>
                 De nouveaux tickets vous ont &eacute;t&eacute; affect&eacute;s; vous &ecirc;tes invit&eacute;(e) &agrave; vous connecter &agrave; votre Tableau de bord pour en prendre connaissance.
              <br>
              <br>
              <p>
              Cordialement,
              <br>
              Votre &eacute;quipe Brightwatch
              <br>
              <br>
              N.B: ceci est un message automatique, merci de ne pas y r&eacute;pondre.
                  </p>

              </body>
              </html>
              """

                part2 = MIMEText(html, "html")

                message.attach(part2)

                published_on = send_mime_mail_assign_ticket(receiver, message)
            return {
                "message": "success"
            }, 201

        return {
            "message": "error"
        }, 404


@app.route('/list-vuls_dash_v2', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_vuls_v2():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    tickets = user.get_tickets()
    assets = user.get_client_assets()
    services = client_group.get_subscription_info()
    Ass = m.Asset.query.filter_by(manager=current_user_id).all()
    vuls = []
    liste_tickets_by_assets = []
    out2_liste_vuls = []
    liste_vuls = []
    liste_vlus2 = []
    liste_vuls_chart1 = []
    liste_vuls_chart2 = []
    liste_vuls_chart = []
    liste_vuls_chart3 = []
    liste_service_pie = []
    nombre_actif = []
    liste_pie1 = []
    liste1 = []
    out8 = []
    out5_vuls = []
    out10 = []
    out9 = []
    out1 = []
    out2 = []
    out3 = []
    out4 = []
    out5 = []
    out6 = []
    out7 = []
    outputDelta = []
    listeSorted = []
    listeDelta = []
    listeTaux = []
    listeMonth = []
    deltaTime = 0
    somme = 0
    delta = 0
    listeDate = []
    listMonth = []
    liste_count_tickets_services = []
    liste_count_services_names = []
    outputTicketsServices = []
    count_en_attente = 0
    count_en_cours = 0
    count_traites = 0
    count_fermes = 0
    taux_date_dict = {}
    nb_vul = 0
    month_index = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]

    if len(tickets) > 0:
        list_cves_len = []
        # tickets_23 = sorted(tickets, key=itemgetter('cve'))
        tickets_23 = sorted(tickets, key=lambda x: defaultdict(str, x).get('cve') or '')
        list_cves_len = list(filter(lambda x: x != '', map(itemgetter('cve'), tickets_23)))
        nb_vul = len(list_cves_len)
        for n in tickets:
            dict_taux = {}
            dict_delta = {}
            dict_re = {}
            dict_chart4 = {}
            dict_chart1 = {}
            dict_chart2 = {}
            dict_chart3 = {}
            dict_actif = {}
            dict_final = {}
            dict_re['cve'] = n['cve']
            dict_re['date'] = n['created_at']
            if n['score']:
                dict_re['score'] = n['score']
            else:
                dict_re['score'] = 0
            dict_re['asset_ref'] = n['asset_ref']
            dict_re['id'] = n['id']
            dict_actif['cve'] = n['cve']
            dict_actif['asset_ref'] = n['asset_ref']
            dict_chart1['cve'] = n['cve']

            if n['score']:
                dict_chart2['score'] = round(n['score'])
            else:
                dict_chart2['score'] = 0
            dict_chart3['cve'] = n['cve']
            dict_chart3['status'] = n['status']
            dict_chart1['month'] = dti.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S').strftime("%B")
            vuls.append(dict_re)
            liste_vuls_chart1.append(dict_chart1)
            liste_vuls_chart.append(dict_chart2)
            liste_vuls_chart3.append(dict_chart3)
            nombre_actif.append(dict_actif)

            if n['status'] == 0:
                count_en_attente = count_en_attente + 1
            elif n['status'] == 1:
                count_en_cours = count_en_cours + 1

            elif n['status'] == 2:
                count_traites = count_traites + 1
            else:
                count_fermes = count_fermes + 1
            dict_asset_top = {}
            dict_asset_top['id_ticket'] = n['id']
            dict_asset_top['asset_ref'] = n['asset_ref']
            liste_tickets_by_assets.append(dict_asset_top)

        vuls_2 = sorted(vuls, key=lambda x: defaultdict(str, x).get('cve') or '')
        for element in Ass:
            dict1 = {}
            dict1['asset_ref'] = element.asset_ref
            dict1['status'] = element.status
            liste_pie1.append(dict1)
        listeSortedServiceName = sorted(tickets, key=itemgetter("name"))
        for i, j in groupby(listeSortedServiceName, key=itemgetter("name")):
            outputTicketsServices.append(list(j))
        for element in outputTicketsServices:
            liste_count_tickets_services.append(len(element))
            for souselement in element:
                liste_count_services_names.append(souselement['name'])
                break

        month_index = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ]
        liste_mois = []
        for e, f in groupby(vuls_2, key=itemgetter("cve")):
            out2_liste_vuls.append(list(f))
        liste_vuls.sort(key=lambda date: date.created_at)
        try:
            liste_vuls_chart4 = sorted(liste_vuls_chart3, key=itemgetter('status'))
        except Exception:
            liste_vuls_chart4 = liste_vuls_chart3
        finally:
            liste_vuls_chart4 = liste_vuls_chart3
        liste1 = sorted(liste_pie1, key=itemgetter('status'))
        liste_vuls = vuls[0:5]
        outputList = []
        outputList2 = []
        outputList3 = []
        outputList4 = []
        outputList5 = []
        liste_vuls_chart2 = sorted(liste_vuls_chart, key=itemgetter('score'))
        for a, b in groupby(liste_vuls_chart1, key=itemgetter("month")):
            outputList.append(list(b))
        for l, s in groupby(liste1, key=itemgetter("status")):
            outputList5.append(list(s))
        for e, f in groupby(liste_vuls_chart4, key=itemgetter("status")):
            outputList3.append(list(f))
        for n, k in groupby(liste_vuls_chart2, key=itemgetter("score")):
            outputList2.append(list(k))
        for h, j in groupby(nombre_actif, key=itemgetter("cve")):
            outputList4.append(list(j))
        for elemen5 in outputList5:
            for e5 in elemen5:
                out9.append(e5['status'])
                break
            taille = len(elemen5)
            out10.append(taille)
        for elemen2 in outputList2:
            for e2 in elemen2:
                out3.append(e2['score'])
                break
            taille = len(elemen2)
            out4.append(taille)
        for elemen3 in outputList3:
            for e3 in elemen3:
                out5.append(e3['status'])
                break
            taille = len(elemen3)
            out6.append(taille)
        for element in outputList:
            for e in element:
                out1.append(e['month'])
                break
            taille = len(element)
            out2.append(taille)
        for elemen4 in outputList4:
            for e4 in elemen4:
                out7.append(e4['cve'])
                break
            taille = len(elemen4)
            out8.append(taille)
        for e in out2_liste_vuls:
            dict_re_vuls = {}
            for x in e:
                dict_re_vuls['cve'] = x['cve']
                dict_re_vuls['score'] = x['score']
                dict_re_vuls['date'] = x['date']
                dict_re_vuls['asset_ref'] = x['asset_ref']
                dict_re_vuls['id'] = x['id']
                break
            taille = len(e)
            dict_re_vuls['nb_actifs_cve'] = taille
            out5_vuls.append(dict_re_vuls)
            try:
                out5_vuls = sorted(out5_vuls, key=itemgetter('score'), reverse=True)
            except:
                out5_vuls = out5_vuls
            finally:
                out5_vuls = out5_vuls
        out5_vuls = out5_vuls[0:5]
    list_status = []
    for element in Ass:
        dict_status = {}
        dict_status['asset_ref'] = element.asset_ref
        dict_status['status'] = element.status
        list_status.append(dict_status)
    count_status_0 = 0
    count_status_1 = 0
    for element in list_status:
        if element['status'] == 0:
            count_status_0 = count_status_0 + 1
        else:
            count_status_1 = count_status_1 + 1
    closed_tickets = user.get_closed_tickets()
    liste_vuls_chart6 = sorted(liste_tickets_by_assets, key=itemgetter('asset_ref'))
    outputList1_tickets_assets = []
    outputList2_assets_x = []
    for n, k in groupby(liste_vuls_chart6, key=itemgetter("asset_ref")):
        outputList1_tickets_assets.append(list(k))
    if len(outputList1_tickets_assets) > 5:
        outputList2_tickets_assets = outputList1_tickets_assets[
                                     len(outputList1_tickets_assets) - 3:len(outputList1_tickets_assets)]
    else:
        outputList2_tickets_assets = outputList1_tickets_assets

    for element in outputList2_tickets_assets:
        for e in element:
            dict_assets_length = {}
            dict_assets_length['asset_ref'] = e['asset_ref']
            break
        taille = len(element)
        dict_assets_length['size'] = taille
        outputList2_assets_x.append(dict_assets_length)
    services = client_group.get_services()
    nb_assets = len(Ass)
    nb_service = len(services)
    closed_tickets = user.get_closed_tickets()
    listeDate = []
    for n in closed_tickets:
        if n['closed_at']:
            dict_delta = {}
            dict_delta['open'] = dti.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S')
            dict_delta['close'] = dti.datetime.strptime(n['closed_at'], '%Y-%m-%d %H:%M:%S')
            dict_delta['id'] = n['id']
            listeDate.append(dict_delta)
    for element in listeDate:
        dict_taux = {}
        delta = element['close'] - element['open']
        dict_taux['delta'] = delta.days
        dict_taux['Month'] = element['close'].strftime("%m")
        listeTaux.append(dict_taux)
    listeSorted = sorted(listeTaux, key=itemgetter("Month"))
    for i, j in groupby(listeSorted, key=itemgetter("Month")):
        outputDelta.append(list(j))
    for i in outputDelta:
        for j in i:
            somme = somme + j['delta']
            dict_final['Month'] = j['Month']
        taux = round(somme / len(tickets), 2)
        dict_final['taux'] = taux

        listeDelta.append(dict_final['taux'])
        listeMonth.append(dict_final['Month'])
    liste_mois = []

    for s in listeMonth:
        month_name = dti.datetime(1, int(s), 1).strftime("%B")
        liste_mois.append(month_name)
    for month in month_index:
        if month not in liste_mois:
            liste_mois.insert(month_index.index(month), month)
            listeDelta.insert(month_index.index(month), 0)

    return jsonify({"nombre-actif": out8, "nb_vuls": nb_vul, "nb_services": nb_service, "nb_assets": nb_assets,
                    "liste_vuls": out5_vuls, "liste_vuls_pie_y": out10, "liste_vuls_pie_x": out9,
                    "liste_vuls3_chart3_x": out5, "liste_vuls3_chart3_y": out6, "liste_vuls_chart1_x": out1,
                    "liste_vuls_chart1_y": out2, "liste_vuls2_chart2_x": out3, "liste_vuls2_chart2_y": out4,
                    "listeDelta": listeDelta, "services_tickets_name": liste_count_services_names,
                    "tickets_services_count": liste_count_tickets_services, 'count_en_attente': count_en_attente,
                    'count_en_cours': count_en_cours, 'count_traites': count_traites,
                    'count_fermes': len(closed_tickets), 'outputList2_assets_x': outputList2_assets_x})


@app.route('/liste-products', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_products_assets_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    assets = m.Asset.query.filter_by(manager=user.id).all()
    liste_assets = []
    for element in assets:
        dict_assets = {}
        dict_assets['label'] = element.asset_ref
        dict_assets['value'] = element.asset_ref
        liste_assets.append(dict_assets)

    products_assets = user.get_client_assets()

    liste_products = []
    for element in products_assets:
        dict_products = {}
        dict_products['asset_ref'] = element['asset_ref']

        if element['cpe']:
            cpe = m.Client_cpe.query.filter_by(id_cpe=element['cpe']).first_or_404()

            dict_products['cpe'] = element['cpe']
            dict_products['cpe_readable'] = cpe.get_full_product_name()
        liste_products.append(dict_products)

    return jsonify({'assets': liste_assets, 'products': liste_products})


@app.route('/list-alerts')
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def get_list_alerts():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user:
        alerts = m.Aut_alert.query.filter_by(responsable=current_user_id).all()
        list_alerts = []
        now = dti.datetime.now()
        for element in alerts:
            dict_alert = {}
            dict_alert['id'] = element.id
            dict_alert['created_at'] = element.created_at
            list_alerts.append(dict_alert)
        listeSortedAlerts = sorted(list_alerts, key=itemgetter("created_at"), reverse=True)
        first_items = listeSortedAlerts[0:5]
        print('first_items', first_items)
        return jsonify(first_items)


@app.route('/asset-api/list-all-collab')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def s_assets_api():
    """ Show all assets of the client (user) """
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "ad_user":
        return jsonify("chaine vide")
    else:
        assets = m.Asset.query.filter_by(responsable=current_user_id).all()
        liste_assets = []
        for element in assets:
            dict_asset = {}
            dict_asset['id'] = element.id
            dict_asset['asset_ref'] = element.asset_ref
            dict_asset['groupe'] = element.groupe
            dict_asset['status'] = element.status
            dict_asset['importance'] = element.importance
            s = m.Service.query.filter_by(id=element.service).first_or_404()
            dict_asset['service'] = s.name
            print(dict_asset)
            liste_assets.append(dict_asset)
        return jsonify(liste_assets)


@app.route('/contact-support', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def mail_sent_contact():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    sender_email = 'pgv.brightway@gmail.com'
    receiver = 'asma.sehli.96@gmail.com'
    subject = request.form.get('subject')
    message_contact = request.form.get('message')
    file = request.files['file']
    new_file = m.Support(subject=subject, attachment=file.read(), message=message_contact, company=client_group.id,
                         user=user.id)
    db.session.add(new_file)
    db.session.commit()
    filename = secure_filename(file.filename)
    new_path = os.path.join('/new/path', file.filename)
    file.save(filename)
    message = MIMEMultipart()

    file_size = os.path.getsize(filename)
    if file_size == 0:
        print("File is empty:", filename, 'path', os.path.getsize(filename))
    if os.access(os.path.dirname(filename), os.W_OK):
        print('Write permission is granted.')
    else:
        print('Write permission is not granted.')
    with open(filename, 'rb') as f:
        # Read the image data
        file_data = f.read()
        # Create a MIME base object
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(file_data)
        # Encode the file data

        # Set the attachment filename
        attachment.add_header('Content-Disposition', 'attachment', filename=filename)
        # Attach the file to the message
        message.attach(attachment)

    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver
    message.attach(MIMEText(message_contact))
    published_on = send_mime_mail(receiver, message)

    return jsonify({"message": "message envoy� avec succ�s"})


@app.route('/ticket-ticket-history/<ticket_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def ticket_ticket_history_api(ticket_id):
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    ticket = m.Ticket.query.filter_by(id=ticket_id).first_or_404()
    t = ticket.get_ticket(user.id)
    ticket_hist_list = []
    if t:

        histories = m.Ticket_history.query.filter_by(ticket_id=ticket_id).all()

        titles = {0: "En attente", 1: "En cours de traitement", 2: "Traité", 3:"Fermé"}

        if histories:
            for element in histories:
                dict_hist = {}
                dict_hist['id'] = element.id
                dict_hist['title'] = element.opened_at
                dict_hist['cardDetailedText'] = element.comment
                dict_hist['cardSubtitle'] = element.action
                modifiedAt = element.modified_at
                if element.status in titles:
                    if modifiedAt:
                        modified_date_formated = modifiedAt.strftime('%d/%m/%Y %H:%M:%S')
                        dict_hist['cardTitle'] = titles[element.status] + " - " + modified_date_formated
                    else:
                        dict_hist['cardTitle'] = titles[element.status]
                ticket_hist_list.append(dict_hist)

    return jsonify(ticket_hist_list)


@app.route('/import-assets-api', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def import_assets_api_products():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role  == 'ad_user':
      file = request.files['file']
      filename = secure_filename(file.filename)
      file_extension = pathlib.Path(filename).suffix
      if file_extension not in app.config['ALLOWED_EXTENSIONS']:
          message = 'Imported successfully'
          return jsonify({'message': message}), 401
      file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
      print("file path !!!!!!", file_path)
      file.save(file_path)
      client = m.Client_group.query.filter_by(id=user.groupe).first()
      client_info = client.get_all_info()
      cpe_credits = int(client_info['cpe_credits']) - int(
          client_info['nb_products'])  # calculate remaining cpe credits
      """ Importing new assets"""
      import_results = client.import_assets(file_path, cpe_credits)
      message = 'Imported successfully'
      return jsonify({'message': message})

    else :

        message = 'You are not authorized'
        return jsonify({'message': message}), 401












@app.route('/asset-add-product/list-all')
# @login_required
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def ad_product_list_assets_api():
    """ Show all assets of the client (user) """
    """ Show all assets of the client (user) """
    # if not current_user.is_anonymous:
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    if user.role == "s_user":
        return jsonify("chaine vide")
    else:
        assets = m.Asset.query.filter_by(manager=current_user_id).all()
        liste_assets = []
        for element in assets:
            dict_asset = {}
            dict_asset['label'] = element.asset_ref
            dict_asset['value'] = element.asset_ref
            print(dict_asset)
            liste_assets.append(dict_asset)
        return jsonify(liste_assets)


###################################### Cert ################

@app.route("/token-cert", methods=["POST"])
@cross_origin()
def create_token_cert():
    # get username input
    # get password input
    username = request.json.get("username")
    password = request.json.get("password")
    print('username', username)
    user = m.Analyst.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        # the user was not found on the database
        return jsonify({"msg": "Identifiant ou mot de passe incorrect"}), 401

    # create a new token with the user id inside
    expires = dti.timedelta(days=2)
    access_token = create_access_token(identity=user.id, expires_delta=expires)
    role = user.role
    l1 = []
    print('role', role)
    response = {"token": access_token, "user_id": user.id, "username": user.username}
    print('response', response)
    return jsonify(response)


@app.route("/token-cert-api", methods=["POST"])
@cross_origin()
def create_cert():
    username = request.json.get("username")
    password = request.json.get("password")
    user = m.Analyst.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({"msg": "Identifiant ou mot de passe incorrect"}), 401
    # Create a token with the user id inside and add a "role" key to the response
    expires = dti.timedelta(days=2)
    token = create_access_token(identity=user.id, expires_delta=expires)
    role = user.role  # Get the string value of the Enum
    if role == 'cert_ad':
        abo = m.Subs_plan.query.all()
        subs = m.Subscription.query.all()
        client = m.Client_group.query.all()
        assets = m.Asset.query.all()
        produits = m.Client_cpe.query.all()
        ticket = m.Ticket.query.all()
        analyst = m.Analyst.query.all()
        nbre_abon = len(abo)
        nbre_subs = len(subs)
        nbre_asset = len(assets)
        nbre_products = len(produits)
        nbre_client = len(client)
        nbre_ticket = len(ticket)
        nbre_analyst = len(analyst)
        response = {
            "token": token,
            "user_id": user.id,
            "username": user.username,
            "role": role,
            "abon": nbre_abon,
            "produits": nbre_products,
            "client": nbre_client,
            "subs": nbre_subs,
            "asset": nbre_asset,
            "analyst": nbre_analyst,
            "ticket": nbre_ticket

        }
    elif role == 'cert_user':
        preticket = m.Pre_ticket.query.all()
        assets = m.Asset.query.all()
        produits = m.Client_cpe.query.all()
        ticket = m.Ticket.query.all()
        nbre_preticket = len(preticket)
        nbre_ticket = len(ticket)
        nbre_asset = len(assets)
        nbre_products = len(produits)
        response = {
            "token": token,
            "asset": nbre_asset,
            "produits": nbre_products,
            "ticket": nbre_ticket,
            "preticket": nbre_preticket,
            "user_id": user.id,
            "username": user.username,
            "role": role
        }
    else:
        return jsonify({"msg": "R�le d'utilisateur invalide"}), 401

    return jsonify(response)


@app.route("/list-services-cert-api", methods=["GET"])
@cross_origin()
def list_service_cert():
    services = m.Service.query.all()
    list_services = []
    for element in services:
        dict_service = {}
        dict_service['name'] = element.name
        dict_service['id'] = element.id
        list_services.append(dict_service)
    print('services', list_services)
    return jsonify(list_services)


@app.route("/list-client-groups-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_client_groups_cert():
    current_user_id = get_jwt_identity()
    clients = m.Client_group.query.all()
    list_clients = []
    for element in clients:
        dict_client = {}
        dict_client['name'] = element.name
        dict_client['id'] = element.id
        dict_client['type'] = element.type
        if element.subscription:
            sub = m.Subscription.query.filter_by(id=element.subscription).first_or_404()
            abon = m.Subs_plan.query.filter_by(id=sub.type).first_or_404()
            dict_client['subscription'] = abon.name
        else:
            dict_client['subscription'] = ""
        list_clients.append(dict_client)
    return jsonify(list_clients)


@app.route("/list-abonnement-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_abonnement_api():
    subs_plans = m.Subs_plan.query.all()
    liste_subs = []
    for element in subs_plans:
        subs_dict = {}
        subs_dict['name'] = element.name
        subs_dict['user_credits'] = element.user_credits
        subs_dict['cpe_credits'] = element.cpe_credits
        subs_dict['id'] = element.id
        liste_subs.append(subs_dict)
    return jsonify(liste_subs)


@app.route("/register-user-api", methods=["POST"])
@cross_origin()
@jwt_required()
def register_user_api():
    current_user_id = get_jwt_identity()
    username = request.json.get('username')
    prenom = request.json.get('surname')
    nom = request.json.get('name')
    email = request.json.get('email')
    country_code = request.json.get('country_code')
    phone = request.json.get('phone')
    groupe = request.json.get('groupe')
    role = request.json.get('role')
    role_value = ""
    if role == "Admin":
        role_value = "ad_user"
    else:
        role_value = "s_user"

    password = request.json.get('password')
    cl_group = m.Client_group.query.filter_by(name=groupe).first_or_404()
    user = m.User(username=username, nom=nom, prenom=prenom, email=email,
                  country_code=country_code, phone=phone, groupe=cl_group.id, role=role_value, status=1)
    user.set_password(password)
    secret = pyotp.random_base32()
    user.secret_2fa = secret
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "user added sccessfully"}), 201


@app.route("/register-client-api", methods=["POST"])
@cross_origin()
@jwt_required()
def register_client_api():
    """ Add new user to the database """
    # if current_user.is_authenticated:
    #     return redirect(url_for('index'))
    current_user_id = get_jwt_identity()
    client_name = request.json.get('client_name')
    description = request.json.get('company_description')
    client = m.Client_group(name=client_name, type=description, alerts=1)
    db.session.add(client)
    db.session.commit()
    return jsonify({"message": "client added sccessfully"}), 201


@app.route("/add-subscription-api", methods=["POST"])
@cross_origin()
@jwt_required()
def add_subscription_api():
    client_name = request.json.get('client_name')
    subscription_name = request.json.get('subscription_name')
    client_group = m.Client_group.query.filter_by(name=client_name).first_or_404()
    sub_plan = m.Subs_plan.query.filter_by(name=subscription_name).first_or_404()
    date_now = dti.datetime.now()
    expire_date = date_now + relativedelta(months=24)
    subscription = m.Subscription(type=sub_plan.id, start_at=dti.datetime.now(),
                                  expire_on=expire_date)
    subscription.client = client_group
    db.session.add(subscription)
    db.session.commit()
    return jsonify({"message": "client subscription added sccessfully"}), 201


@app.route("/add-abonnement-api", methods=["POST"])
@cross_origin()
@jwt_required()
def add_abonnement_api():
    abo_name = request.json.get('name')
    user_credits = request.json.get('user_credits')
    cpe_credits = request.json.get('cpe_credits')
    sub_plan = m.Subs_plan(name=abo_name, user_credits=user_credits,
                           cpe_credits=cpe_credits)
    db.session.add(sub_plan)
    db.session.commit()
    return jsonify({"message": "Abonnement added successfully"}), 201


@app.route("/modify-abonnement-api", methods=["POST"])
@cross_origin()
@jwt_required()
def modify_abonnement_api():
    abo_name = request.json.get('name')
    user_credits = request.json.get('user_credits')
    cpe_credits = request.json.get('cpe_credits')
    sub_plan = m.Subs_plan.query.filter_by(name=abo_name).first_or_404()
    sub_plan.user_credits = user_credits
    sub_plan.cpe_credits = cpe_credits
    db.session.commit()
    return jsonify({"message": "Abonnement added successfully"}), 201


@app.route("/modify-subscription-api", methods=["POST"])
@cross_origin()
@jwt_required()
def modify_subscription_api():
    client_name = request.json.get('client_name')
    subscription_name = request.json.get('subscription_name')
    start_at = request.json.get('start_at')
    expire_at = request.json.get('expire_at')
    client_group = m.Client_group.query.filter_by(name=client_name).first_or_404()
    sub_plan = m.Subs_plan.query.filter_by(name=subscription_name).first_or_404()
    subscription = m.Subscription(type=sub_plan.id, start_at=start_at,
                                  expire_on=expire_at)
    subscription.client = client_group
    db.session.add(subscription)
    db.session.commit()
    return jsonify({"message": "subscription modified succesfully"}), 201


@app.route("/list-subscription-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_subs():
    client = m.Client_group.query.all()
    list_cl_sub = []
    for i in client:
        dict_list_sub = {}
        dict_list_sub['name'] = i.name
        if i.subscription:
            sub = m.Subscription.query.filter_by(id=i.subscription).first()
            print(sub)
            dict_list_sub['Date_de_debut'] = dti.datetime.strftime((sub.start_at), '%d %B %Y')
            dict_list_sub['Date_de_fin'] = dti.datetime.strftime((sub.expire_on), '%d %B %Y')
            dict_list_sub['ID'] = sub.id
            dict_list_sub['Status'] = sub.status
            abon = m.Subs_plan.query.filter_by(id=sub.type).first()
            print(abon)
            if abon:
                dict_list_sub['Type'] = abon.name
            else:
                dict_list_sub['Type'] = 'Unknown'
            list_cl_sub.append(dict_list_sub)
    return jsonify(list_cl_sub)


import heapq
from sqlalchemy import func


@app.route("/dashboard-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def dashboard_cert():
    # nombre d'abonnement par type d'abonnement
    result = db.session.query(
        m.Subs_plan.name, func.count(m.Subs_plan.id).label('nombre_abonnements')
    ).group_by(m.Subs_plan.name).all()

    liste_type_abonnement = []  # List to store subscription types
    liste_nombre_abonnements = []  # List to store number of subscriptions

    for r in result:
        liste_type_abonnement.append(r.name)
        liste_nombre_abonnements.append(r.nombre_abonnements)


    # Nombre d'inscription par mois
    sub = m.Subscription.query.all()
    inscriptions_par_mois = defaultdict(int)
    for inscription in sub:
        mois = dti.datetime.strftime(inscription.start_at,
                                     '%B %Y')  # Extraction du mois � partir de la date d'inscription
        inscriptions_par_mois[mois] += 1

    liste_mois = []  # List to store months
    liste_nombre_inscriptions = []  # List to store number of inscriptions

    for mois, nombre_inscriptions in inscriptions_par_mois.items():
        liste_mois.append(mois)
        liste_nombre_inscriptions.append(nombre_inscriptions)

    # Nombre d'alertes de chaque clients
    result1 = db.session.query(
        m.Client_group.name, func.count(m.Client_group.alerts).label('nombre_alertes')
    ).group_by(m.Client_group.name).all()
    nombre_alertes_par_cleints = []
    for r1 in result1:
        nombre_alertes_par_cleints.append({
            'Company_name': r1.name,
            'nombre_alertes': r1.nombre_alertes
        })
    # Liste des clients avec date de d�but d'abonnement , date de fin d'abonneemnt et le type d'abonnement
    client = m.Client_group.query.all()
    list_name = []
    for element in client:
        dict_name = {}
        dict_name['Nom'] = element.name
        if element.subscription:
            sub = m.Subscription.query.filter_by(id=element.subscription).first()
            dict_name['Date_debut'] = dti.datetime.strftime((sub.start_at), '%a%d %B %Y')
            dict_name['Date_fin'] = dti.datetime.strftime((sub.expire_on), '%a%d %B %Y')
            abon = m.Subs_plan.query.filter_by(id=sub.type).first_or_404()
            dict_name['Type_abonnement'] = abon.name
        list_name.append(dict_name)
    # nombre de collaborateurs par entreprise
    companies_employees = []
    companies = m.Client_group.query.all()
    dict_comp = {}
    for c in companies:
        company_employees = m.User.query.filter_by(groupe=c.id).all()
        print(company_employees)
        # dict_comp["company_name"]= c.name
        # dict_comp["employess_count"]= len(companies_employees)
        companies_employees.append({"company_name": c.name, "users": len(company_employees)})
    # les 5 clients les plus r�cents
    client = m.Client_group.query.all()
    list_cl = []
    for i in client:
        dict_client = {}
        dict_client['name'] = i.name
        if i.subscription:
            sub = m.Subscription.query.filter_by(id=i.subscription).first()
            client= m.Client_group.query.filter_by(subscription=sub.id).first()
            dict_client['Date_debut'] = dti.datetime.strftime((sub.start_at), '%d %B %Y')
            dict_client['Date_fin'] = dti.datetime.strftime((sub.expire_on), '%d %B %Y')
            dict_client['ID'] = sub.id
            dict_client['name']= client.name
            dict_client['Status'] = sub.status
        list_cl.append(dict_client)
        clients_tries = sorted(list_cl, key=lambda x: x.get('Date_debut', '%d %B %Y'), reverse=True)
        top_5_clients = heapq.nlargest(5, clients_tries, key=lambda x: x.get('Date_debut', '%d %B %Y'))
        # print(top_5_clients)
    # Les kpis
    subs = m.Subs_plan.query.all()
    users = m.User.query.all()
    tickets = m.Ticket.query.all()
    assets = m.Asset.query.all()
    list_kpis = []

    dict_kpis = {}
    dict_kpis['ticket'] = len(tickets)
    ass= len(assets)
    dict_kpis['subs'] = len(subs)
    dict_kpis['users'] = len(users)
    dict_kpis['assets'] = len(assets)
    list_kpis.append(dict_kpis)

    return jsonify({ "liste_type_abonnemen":liste_type_abonnement,"liste_nombre_abonnements.":liste_nombre_abonnements,
                     "liste_mois": liste_mois, "liste_nombre_inscriptions":liste_nombre_inscriptions,
                    "nb_alertes_clients": nombre_alertes_par_cleints,
                    "subs": len(subs),"users":len(users),"ticket":len(tickets),
                    "company_list": list_name, "Les KPIs": list_kpis, "assets":ass,
                    "nb_collab_company": companies_employees,
                    "top5": top_5_clients})


@app.route('/dashboard-analyst-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def dashboard_analyst():
    ####### KPIs ##########
    pretickets = m.Pre_ticket.query.all()
    tickets = m.Ticket.query.all()
    tickets_fermes = m.Ticket.query.filter_by(status=-1).all()
    assets = m.Asset.query.all()
    vuln = m.Cve_temp.query.all()
    user = m.User.query.all()
    dict_analyst_kpis = {}
    dict_analyst_kpis['pretickets'] = len(pretickets)
    dict_analyst_kpis['tickets'] = len(tickets)
    dict_analyst_kpis['tickets_fermes'] = len(tickets_fermes)
    dict_analyst_kpis['actifs'] = len(assets)
    dict_analyst_kpis['vulnerabilities'] = len(vuln)
    dict_analyst_kpis['utilisateurs'] = len(user)
    tickets_ouverts = 0
    for ticket in tickets:
        if ticket not in tickets_fermes:
            tickets_ouverts += 1
    dict_analyst_kpis['tickets_ouverts'] = tickets_ouverts
    print(dict_analyst_kpis)
    ############# Tickets by month###################
    result = db.session.query(func.count(m.Ticket.id), func.DATE_FORMAT(m.Ticket.created_at, '%Y-%m')).group_by(
        func.DATE_FORMAT(m.Ticket.created_at, '%Y-%m')).all()
    tickets_by_month = {}
    for count, month in result:
        month_str = month  # Conversion de l'objet datetime en cha�ne de caract�res
        tickets_by_month[month_str] = count
    ############## Pretickets by month ##########
    result1 = db.session.query(func.count(m.Pre_ticket.id), func.DATE_FORMAT(m.Pre_ticket.created_at, '%Y-%m')).group_by(
        func.DATE_FORMAT(m.Pre_ticket.created_at, '%Y-%m')).all()
    Pretickets_by_month = {}
    for count, month in result1:
        month_str = month  # Conversion de l'objet datetime en cha�ne de caract�res
        Pretickets_by_month[month_str] = count

    ############### nombre de ticket par �tat ####################
    status_counts = {
        'ferm�': m.Ticket.query.filter_by(status=-1).count(),
        'trait�': m.Ticket.query.filter_by(status=2).count(),
        'en traitement': m.Ticket.query.filter_by(status=1).count(),
        'en attente': m.Ticket.query.filter_by(status=0).count()
    }
    ################# nombre de vuln�rabilit� par mois #########################
    result2 = db.session.query(func.count(m.Cve_temp.id), m.Cve_temp.published_at).group_by(
        m.Cve_temp.published_at).all()
    cve_counts = {date.strftime('%Y-%m'): count for count, date in result2 if date is not None}

    return jsonify(kpis=dict_analyst_kpis, tickets_by_month=tickets_by_month, pretickets_by_month= Pretickets_by_month, status_count= status_counts, cve_pub= cve_counts)




@app.route('/forgot-password-cert-api/send-email', methods=['POST'])
@cross_origin()
def send_token_to_email_cert():
    input_email = request.json.get('email')

    analyst = m.Analyst.query.filter_by(email=input_email).first()
    if analyst is None:
        return jsonify({"message": "Aucun analyste avec cette adresse e-mail n'a �t� trouv�."}), 404
    generated_token = str(uuid.uuid4())
    token = m.password_reset_cert(analyst_id=analyst.id, token=generated_token)
    db.session.add(token)
    db.session.commit()
    base_url = "http://localhost:3000/brightwatch-cert/user-pages/reset-password/?token="
    sender = "pgv.brightway@gmail.com"
    content = base_url + generated_token
    html = f"""\
        <html>
        <body>
        <p>
            Bonjour,
            <br>
            <br>
            <p>Veuillez cliquer <a target="_blank" href="{content}">ici</a> pour finaliser le changement.</p>
            <br>
            <br>
        <p>
            Cordialement,
            <br>
            Equipe Brightwatch
            <br>
            <br>

        </p>

        </body>
        </html>
        """.format(content=content)
    message = MIMEMultipart("alternative")
    subject = "Brightwatch | R�initialiser Votre Mot de Passe."
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = input_email
    part = MIMEText(html, _subtype="html")
    message.attach(part)
    published_on = send_mime_mail(input_email, message)
    return jsonify({"message": "message envoy� avec succ�s"})


@app.route("/reset-password-cert-api", methods=["POST"])
@cross_origin()
@jwt_required()
def reset_password_cert():
    get_token = request.json.get('token')
    # print(get_token)
    get_password = request.json.get('password')
    token = m.password_reset_cert.query.filter_by(token=get_token).first()
    if token is None:
        return jsonify({"message": "Le jeton de r�initialisation de mot de passe est invalide ou a expir�."}), 400
    print(token)
    token_time = dti.datetime.now() - token.expiration_date
    expiration = datetime.timedelta(days=1)
    if token_time > expiration:
        return jsonify({"message": "token expir�"}), 401
    analyst_id = token.analyst_id
    analyst = m.Analyst.query.filter_by(id=analyst_id).first_or_404()
    analyst.set_password(get_password)
    db.session.add(analyst)
    db.session.delete(token)
    db.session.commit()
    return jsonify({"message": " mot de passe chang� avec succ�s"})


@app.route("/list-alert-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_alertes_cert():
    liste_alertes = []
    alertes = m.Support.query.all()
    for i in alertes:
        dict_alertes = {}  # initialiser le dictionnaire ici
        dict_alertes['id'] = i.id
        dict_alertes['created_at'] = i.created_at
        companies = m.Client_group.query.filter_by(id=i.company).all()
        company_names = []
        for company in companies:
            company_names.append(company.name)
        dict_alertes['company'] = company_names
        liste_alertes.append(dict_alertes)
    return jsonify(liste_alertes)


import base64


@app.route("/detail-alert-cert-api/<alert_id>", methods=["GET"])
@cross_origin()
@jwt_required()
def detail_alert(alert_id):
    alert = m.Support.query.filter_by(id=alert_id).first_or_404()
    user = m.User.query.filter_by(id=alert.user).first_or_404()
    dict_detail_alert = {}
    dict_detail_alert['Date_envoie'] = alert.created_at
    dict_detail_alert['Message'] = alert.message
    dict_detail_alert['Name_user'] = user.username
    dict_detail_alert['Subject'] = alert.subject
    if alert.attachment:
        dict_detail_alert['attachement'] = base64.b64encode(alert.attachment).decode('utf-8')
    else:
        dict_detail_alert['attachement'] = None
    return jsonify(dict_detail_alert)


@app.route('/list-products-cert-api', methods=["GET"])
@cross_origin()
@jwt_required()
def list_product_cert():
    products = m.Client_cpe.query.all()
    list_produits = []
    for i in products:
        dict_produits = {}

        dict_produits['name'] = i.name
        dict_produits['type'] = i.type
        dict_produits['version'] = i.version
        dict_produits['producer'] = i.producer
        dict_produits['id'] = i.id_cpe
        list_produits.append(dict_produits)
    return jsonify(list_produits)


@app.route('/list-ticket-ferme-cert-api', methods=["GET"])
@cross_origin()
@jwt_required()
def list_ticket_ferme():
    closed_tickets = m.Ticket.query.filter_by(status=-1).all()
    ticket_ferme = []

    for ticket in closed_tickets:
        if ticket in closed_tickets:
            dict = {}
            manager = m.User.query.filter_by(id=ticket.manager).first()
            if manager is not None:
                dict['manager'] = manager.username
            responsable = m.User.query.filter_by(id=ticket.responsable).first()
            if responsable is not None:
                dict['responsable'] = responsable.username
            dict['id'] = ticket.id
            dict['created_at'] = ticket.created_at
            dict['closed_at'] = ticket.closed_at
            dict['due_date'] = ticket.due_date
            dict['read'] = ticket.read
            dict['status'] = ticket.status
            dict['comment'] = ticket.comment
            ticket_ferme.append(dict)
    return jsonify(ticket_ferme)


@app.route("/list-ticket-ouvert-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def tickets_ouvert_get_api():
    closed_tickets = m.Ticket.query.filter_by(status=-1).all()
    all_tickets = m.Ticket.query.all()
    # analyst_id = get_jwt_identity()
    # analysts = m.Analyst.query.all()
    list_tickets = []
    for ticket in all_tickets:
        if ticket not in closed_tickets:
            dict = {}
            manager = m.User.query.filter_by(id=ticket.manager).first()
            if manager is not None:
                dict['manager'] = manager.username
            responsable = m.User.query.filter_by(id=ticket.responsable).first()
            if responsable is not None:
                dict['responsable'] = responsable.username
            dict['id'] = ticket.id
            dict['created_at'] = ticket.created_at
            dict['due_date'] = ticket.due_date
            dict['read'] = ticket.read
            dict['status'] = ticket.status
            dict['comment'] = ticket.comment
            list_tickets.append(dict)
        # analyst_tickets = analyst.get_tickets_cert()
        # tickets += analyst_tickets
    return jsonify(list_tickets)


@app.route("/list-ticket-detail-cert-api/<id_ticket>", methods=["GET"])
@cross_origin()
@jwt_required()
def tickets_detail_get_api(id_ticket):
    ticket = m.Ticket.query.filter_by(id=id_ticket).first()
    dict = {}
    cve = m.Cve_temp.query.filter_by(id=ticket.cve).first()
    manager = m.User.query.filter_by(id=ticket.manager).first()
    if manager is not None:
        dict['manager'] = manager.username
    responsable = m.User.query.filter_by(id=ticket.responsable).first()
    if responsable is not None:
        dict['responsable'] = responsable.username
    dict['id'] = ticket.id
    dict['created_at'] = ticket.created_at
    dict['due_date'] = ticket.due_date
    dict['read'] = ticket.read
    dict['status'] = ticket.status
    dict['comment'] = ticket.comment
    dict['action'] = ticket.action
    dict['info'] = ticket.info
    dict['cve'] = cve.description
    dict['title'] = cve.title
    return jsonify(dict)


@app.route('/ajout-ticket-cert-api', methods=["POST"])
@cross_origin()
@jwt_required()
def add_ticket_cert_api():
    cpe_list = []
    for cpe in m.Client_cpe.query.all():
        cpe_list.append(cpe.name)

    asset_list = []
    for asset in m.Asset.query.all():
        asset_list.append(asset.asset_ref)

    cpe = request.json.get("cpe")
    username = request.json.get("user")
    user = m.User.query.filter_by(username=username).first()

    special_characters = "!@#$%^&*()+?=<>/"
    print('cpe', cpe)
    if not cpe:
        print('cpe', cpe)
        print("le champ produit est obligatoire ")
        return jsonify({"erreur": "le champ produit est obligatoire ", "cpe_list": cpe_list, "asset_list": asset_list})
    asset = request.json.get("asset")
    print('asset', asset)
    if not asset:
        print('asset', asset)
        print("le champ actif est obligatoire ")
        return jsonify({"erreur": "le champ actif est obligatoire ", "cpe_list": cpe_list, "asset_list": asset_list})

    score = float(request.json.get("score"))
    asset_instance = m.Asset.query.filter_by(asset_ref=asset).first()
    asset_usage = m.Asset_usage.query.filter_by(cpe=cpe, asset_id=asset_instance.id).first()
    print(asset_usage)

    created_at = dti.datetime.now()
    ticket = m.Ticket(usage_id=asset_usage.id, created_at=created_at, score=float(score), manager=user.id)
    db.session.add(ticket)
    db.session.commit()
    return jsonify({"success": "ticket added successfully", "cpe_list": cpe_list, "asset_list": asset_list}), 201


@app.route('/add-product-cert-api', methods=['POST'])
@cross_origin()
@jwt_required()
def add_product_cert_api():
    asset_ref = request.json.get('asset_ref')
    ass = m.Asset.query.filter_by(asset_ref=asset_ref).first()
    user = m.User.query.filter_by(id=ass.manager).first()
    client = m.Client_group.query.filter_by(id=user.groupe).first()
    client_info = client.get_all_info()
    special_characters = "!@#$%^&*()+?=,<>/"
    if int(client_info['cpe_credits']) <= int(client_info['nb_products']):  # all cpe credits are used
        flash(f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistr�s""")
        flash('Vous avez atteint la limite autoris�e de votre abonnement')
        print("Vous avez atteint la limite autoris�e de votre abonnement")
        return jsonify({'error': "Vous avez atteint la limite autoris�e de votre abonnement"}), 400
    else:
        cpe = m.Client_cpe()
        type = request.json.get('type')
        producer = request.json.get('producer')
        type = "a"
        if type == "OS":
            type = "o"
        if any(c in special_characters for c in producer):
            print("le fournisseur ne peut pas contenir de caract�res sp�ciaux")
            return jsonify({'error': "le fournisseur ne peut pas contenir de caract�res sp�ciaux"}), 201
        producer = normalise_cpe_name(producer)
        name = request.json.get('name')
        if any(c in special_characters for c in name):
            print("le nom ne peut pas contenir de caract�res sp�ciaux")
            return jsonify({'error': "le nom ne peut pas contenir de caract�res sp�ciaux"}), 201
        name = normalise_cpe_name(name)
        if request.json.get('version'):
            version = normalise_cpe_name(request.json.get('version'))
        else:
            version = '*'
        cpe.set_cpe(type=type, producer=producer, name=name, version=version)
        asset = m.Asset.query.filter_by(groupe=user.groupe, asset_ref=asset_ref).first()
        a_u = m.Asset_usage.query.filter_by(cpe=cpe.id_cpe, asset_id=asset.id).first()
        if a_u is None:

            """ Adding the asset_usage to the DB"""
            asset_usage = m.Asset_usage(asset_id=asset.id, cpe=cpe.id_cpe)  # creating asset_usage object
            client_cpe = m.Client_cpe.query.filter_by(id_cpe=cpe.id_cpe).first()  # creating client_cpe object
            if not client_cpe:  # the ne CPE already exists in the DB (client_cpe table)
                client_cpe = cpe
                db.session.add(client_cpe)
            asset_usage.cpes_usage = client_cpe
            db.session.add(asset_usage)
            db.session.commit()
            db.session.expunge_all()
            return jsonify({'success': "Produit Cr�e avec succ�s"}), 201
        else:
            return jsonify({'error': "Produit existe d�j�"}), 400


@app.route('/list-asset-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def get_asset_cert():
    assets = m.Asset.query.all()
    list_assets = []
    for asset in assets:
        dict_asset = {}
        dict_asset['asset_ref'] = asset.asset_ref
        list_assets.append(dict_asset)
    return jsonify(list_assets)


@app.route('/delete-user-cert-api', methods=['POST'])
@cross_origin()
@jwt_required()
def delete_user_cert():
    username = request.json.get('username')
    user = m.User.query.filter_by(username=username).first()
    if user is None:
        return "Utilisateur n'esxiste pas", 404
    else:
        db.session.delete(user)
        db.session.commit()
    return jsonify({"succ�s": "L'utilisateur a �t� supprim� avec succ�s"}), 200


@app.route('/delete-company-cert-api', methods=["POST"])
@cross_origin()
@jwt_required()
def delete_company_cert():
    name = request.json.get('name')
    company = m.Client_group.query.filter_by(name=name).first()
    if company is None:
        return "Company n'existe pas", 404
    else:
        db.session.delete(company)
        db.session.commit()
    return jsonify({"succ�s": "Client a �t� supprim� avec succ�s"}), 200


@app.route('/delete-subscription-cert-api', methods=["POST"])
@cross_origin()
@jwt_required()
def delete_subscription():
    subscription_id = request.json.get('id')
    subs = m.Subscription.query.get(id=subscription_id).first()
    if subs:
        db.session.delete(subs)
        db.session.commit()
        return jsonify({'message': 'Subscription has been deleted'}), 200
    else:
        return jsonify({'error': 'Subscription not found'}), 404


@app.route("/delete-service-cert-api", methods=['POST'])
@cross_origin()
@jwt_required()
def delete_service_by_name_cert():
    service_name = None
    if request.json:
        service_name = request.json.get('service_name')
    if not service_name:
        return jsonify({'error': 'Invalid request data.'}), 400
    service = m.Service.query.filter_by(name=service_name).first()
    if service:
        db.session.delete(service)
        db.session.commit()
        return jsonify({'message': 'Service has been deleted.'}), 200
    else:
        return jsonify({'error': 'Service not found.'}), 404


@app.route("/delete-actif-cert-api/<asset_ref>", methods=["POST"])
@cross_origin()
@jwt_required()
def delete_asset_cert(asset_ref):
    assets = m.Asset.query.filter_by(asset_ref=asset_ref).first()
    if assets:
        db.session.delete(assets)
        db.session.commit()
        return jsonify({"succ�s": "Actif a �t� supprim�"}), 200
    else:
        return jsonify({"erreur": "Actif n'existe pas"}), 404


@app.route("/list-abonnement-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_abonnement():
    sub = m.Subscription.query.all()
    list_abonnements = []
    for element in sub:
        dict_subs = {}
        dict_subs['expire_on'] = element.expire_on
        dict_subs['start_at'] = element.start_at

        if element.client:
            client_group = m.Client_group.query.filter_by(id=element.client).first_or_404()
            dict_subs['name'] = client_group.name

        list_abonnements.append(dict_subs)
    return jsonify(list_abonnements)


@app.route('/client-detail-cert-api/<client_id>', methods=['GET'])
@cross_origin()
@jwt_required()
def detail_client_id(client_id):
    clients = m.Client_group.query.filter_by(id=client_id).first_or_404()
    sub = m.Subscription.query.filter_by(id=clients.subscription).first_or_404()
    abon = m.Subs_plan.query.filter_by(id=sub.type).first_or_404()
    list_client = []
    dict_client = {}
    dict_client['alerts'] = clients.alerts
    dict_client['id'] = clients.id
    dict_client['name'] = clients.name
    dict_client['subscription'] = abon.name
    dict_client['type'] = clients.type
    list_client.append(dict_client)
    return jsonify(list_client)


@app.route('/password-change-cert-api', methods=['POST'])
@cross_origin()
@jwt_required()
def change_password_cert():
    current_user_id = get_jwt_identity()
    analyst = m.Analyst.query.filter_by(id=current_user_id).first()
    if analyst:
        old_password = request.json.get('old_password')
        new_password = request.json.get('password1')
        new_password2 = request.json.get('password2')
        print('oldpassword', old_password)
        print('newpassword', new_password)
        print('new_password_2', new_password2)
        if new_password2 != new_password:
            return jsonify({'msg': "Not Matching! "}), 400
        if not analyst.check_password(old_password):
            return jsonify({'notif': " incorrect password "}), 400
        else:

            analyst.set_password(new_password)
            db.session.commit()
            return jsonify({'msg': 'Password changed ! '}), 200


@app.route('/profile-cert-api', methods=["GET"])
@cross_origin()
@jwt_required()
def cert_profile():
    current_user_id = get_jwt_identity()
    analyst = m.Analyst.query.filter_by(id=current_user_id).first()
    clients = m.Client_group.query.all()
    assets = m.Asset.query.all()
    tickets = m.Ticket.query.all()
    products = m.Client_cpe.query.all()
    services = m.Service.query.all()
    dict_profile = {}
    dict_profile['username'] = analyst.username
    dict_profile['mail'] = analyst.email
    dict_profile['role'] = analyst.role
    dict_profile['phone'] = analyst.phone
    dict_profile['nb_tickets'] = len(tickets)
    dict_profile['nb_services'] = len(services)
    dict_profile['nb_assets'] = len(assets)
    dict_profile['nb_products'] = len(products)
    return jsonify(dict_profile)


@app.route('/add-service-cert-api', methods=['POST'])
@cross_origin()
@jwt_required()
def add_service():
    user_manager = request.json.get('user_manager')
    user_responsable = request.json.get('user_responsable')
    responsable = m.User.query.filter_by(username=user_responsable).first_or_404()
    user = m.User.query.filter_by(username=user_manager).first_or_404()
    name = request.json.get('name')
    localisation = request.json.get('localisation')
    description = request.json.get('description')
    service = m.Service(name=name, manager=user.id, localisation=localisation, description=description,
                        responsable=responsable.id)
    db.session.add(service)
    db.session.commit()
    return jsonify({"success": "Service ajout� avec succ�s "}), 201


@app.route('/detail-client-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def detail_client():
    clients = m.Client_group.query.all()

    print(clients)
    for element in clients:
        dict_client = {}
        dict_client['name'] = element.name
        dict_client['type'] = element.type
        dict_client['id'] = element.id

        if element.subscription:
            sub = m.Subscription.query.filter_by(id=element.subscription).first_or_404()
            abon = m.Subs_plan.query.filter_by(id=sub.type).first_or_404()
            dict_client['subscription'] = abon.name
        else:
            dict_client['subscription'] = ""
    return jsonify(dict_client)


@app.route("/list-asset-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_asset_cert_api():
    assets = m.Asset.query.all()
    asset_list = []
    for element in assets:
        asset_dict = {}
        asset_dict['asset_ref'] = element.asset_ref
        if element.groupe:
            client_group = m.Client_group.query.filter_by(id=element.groupe).first_or_404()
            asset_dict['groupe'] = client_group.name
        else:
            asset_dict['groupe'] = ""

        asset_dict['importance'] = element.importance
        if element.manager:
            user = m.User.query.filter_by(id=element.manager).first_or_404()
            asset_dict['manager'] = user.username
        else:
            asset_dict['manager'] = ""
        if element.service:
            service_inst = m.Service.query.filter_by(id=element.service).first_or_404()
            asset_dict['service'] = service_inst.name
        else:
            asset_dict['service'] = ""
        if element.responsable:
            user = m.User.query.filter_by(id=element.responsable).first_or_404()
            asset_dict['responsable'] = user.username
        else:
            asset_dict['responsable'] = ""
        asset_list.append(asset_dict)

    return jsonify(asset_list)


@app.route('/upload-csv-api', methods=['POST'])
def upload_csv():
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_extension = pathlib.Path(filename).suffix
    if file_extension not in app.config['ALLOWED_EXTENSIONS']:
        flash('Format de fichier non support�!')
    else:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        client = m.Client_group.query.filter_by(id=8).first()
        print('client', client)
        client_info = client.get_all_info()
        cpe_credits = int(client_info['cpe_credits']) - int(
            client_info['nb_products'])  # calculate remaining cpe credits
        """ Importing new assets"""
        import_results = client.import_assets(file_path, cpe_credits)
        if import_results['nb_cpes'] != import_results['cpes']:
            return {
                "message": "duplicated_product"
            }
        if import_results['cpe_credits'] == 0:
            return {
                "message": "Vous avez atteint la limite de produits � ajouter"
            }
        client_info = client.get_all_info()  # Getting product credits information after the import
        print('client_info', client_info)
        return {
            "message": "success"
        }


@app.route("/list-users-cert-api", methods=["GET"])
@cross_origin()
@jwt_required()
def list_users_cert_api():
    users_all = m.User.query.all()
    liste_users = []
    for element in users_all:
        users_dict = {}
        users_dict['username'] = element.username
        users_dict['id'] = element.id
        liste_users.append(users_dict)
    return jsonify(liste_users)


@app.route("/add-asset-cert-api", methods=["POST"])
@cross_origin()
@jwt_required()
def add_assets_cert_api():
    client_name = request.json.get('client_name')
    service_name = request.json.get('service')
    importance = request.json.get('importance')
    user_manager = request.json.get('user_manager')
    user_respo = request.json.get('user_responsable')
    asset_ref = request.json.get('asset_ref')
    manager = m.User.query.filter_by(username=user_manager).first_or_404()
    responsable = m.User.query.filter_by(username=user_respo).first_or_404()
    client = m.Client_group.query.filter_by(name=client_name).first_or_404()
    service = m.Service.query.filter_by(name=service_name).first_or_404()
    asset_id = get_asset_id(asset_ref=asset_ref, groupe_id=client.id)
    if asset_id:
        return jsonify("asset existe d�j�"), 400
    else:
        if importance == "Mineur":
            valueImportance = 1
        elif importance == "Important":
            valueImportance = 2
        elif importance == "Majeur":
            valueImportance = 3
        else:
            valueImportance = 4
        asset = m.Asset(asset_ref=asset_ref, importance=valueImportance, groupe=client.id,
                        service=service.id, responsable=responsable.id, manager=manager.id)
        db.session.add(asset)
        db.session.commit()
        return jsonify({"msg": "success"}), 400


@app.route('/pretickets-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def get_all_pretickets():
    pretickets = m.Pre_ticket.query.all()
    preticket_list = []
    for pt in pretickets:
        preticket_dict = {}
        analyst = m.Analyst.query.filter_by(id=pt.analysed_by).first()
        preticket_dict['id'] = pt.id
        status_mapping = {0: 'En attente', -1: 'Ferm�', 2: 'Trait�', 1: 'En traitement'}
        preticket_dict['status'] = status_mapping.get(pt.status, 'Statut inconnu')
        preticket_dict['score'] = pt.score
        preticket_dict['analysed_by'] = analyst.username
        preticket_list.append(preticket_dict)
    return jsonify(preticket_list)



@app.route('/pretickets-details-cert-api/<id>', methods=['GET'])
@cross_origin()
@jwt_required()
def preticket_details(id):
    preticket = m.Pre_ticket.query.filter_by(id=id).all()
    preticket_list = []
    for pt in preticket:
        preticket_dict = {}
        preticket_dict['cve'] = pt.cve
        preticket_dict['created_at'] = pt.created_at
        preticket_dict['opened_at'] = pt.opened_at
        preticket_dict['treated_at'] = pt.treated_at
        preticket_dict['status'] = pt.status
        preticket_dict['score'] = pt.score
        preticket_dict['recommendation'] = pt.recommendation
        preticket_dict['comment'] = pt.comment
        preticket_list.append(preticket_dict)
    return jsonify(preticket_list)


@app.route('/update-pretickets-cert-api/<pt_id>', methods=['POST'])
@cross_origin()
@jwt_required()
def update_preticket(pt_id):
    pt = m.Pre_ticket.query.filter_by(id=pt_id).first()
    if not pt:
        return jsonify({'error': 'Pre-ticket not found'}), 404
    # Les donn�es sont envoy�es dans le corps de la requ�te en JSON
    data = request.get_json()
    if 'cve' in data:
        pt.cve = data['cve']
    if 'created_at' in data:
        pt.created_at = data['created_at']
    if 'opened_at' in data:
        pt.opened_at = data['opened_at']
    if 'treated_at' in data:
        pt.treated_at = data['treated_at']
    if 'status' in data:
        pt.status = data['status']
    if 'score' in data:
        pt.score = data['score']
    if 'recommendation' in data:
        pt.recommendation = data['recommendation']
    if 'comment' in data:
        pt.comment = data['comment']
    if 'analysed_by' in data:
        pt.analysed_by = data['analysed_by']
    db.session.commit()
    return jsonify({'success': 'Pre-ticket updated successfully'})


##############Obsolescence############

@app.route('/obsolescences-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def get_obsolescences():
    obsolescences = m.Obsolescence.query.all()
    result = []
    for obsolescence in obsolescences:
        obsolescence_data = {}
        obsolescence_data['id'] = obsolescence.id
        obsolescence_data['expiration_date'] = obsolescence.expiration_date
        obsolescence_data['source'] = obsolescence.source
        obsolescence_data['patch'] = obsolescence.patch
        obsolescence_data['version'] = obsolescence.version
        obsolescence_data['support'] = obsolescence.support
        obsolescence_data['eol'] = obsolescence.eol
        obsolescence_data['latest'] = obsolescence.latest
        obsolescence_data['releaseDate'] = obsolescence.releaseDate
        obsolescence_data['latestReleaseDate'] = obsolescence.latestReleaseDate
        obsolescence_data['extendedSupport'] = obsolescence.extendedSupport
        obsolescence_data['lts'] = obsolescence.lts
        obsolescence_data['product_cpe'] = obsolescence.product_cpe
        result.append(obsolescence_data)
    return jsonify(result)


@app.route('/obso-notif-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def notif_obso_cert():
    notif = m.Notif_obsolescence.query.all()
    notifs = []
    for n in notif:
        respo = m.User.query.filter_by(id=n.user_id).first()
        obso = m.Obsolescence.query.filter_by(id=n.obsolescence_id).first()
        product = m.Client_cpe.query.filter_by(name=obso.product_cpe).first()
        print(product)
        if product is not None and respo is not None:
            obso_dict = {
                "eol": obso.eol,
                "product_cpe": obso.product_cpe,
                "responsable": respo.username,
                "version": product.version,
                "type": product.type,
                "fournisseur": product.producer}
        else:
            obso_dict = {
                "eol": obso.eol,
                "product_cpe": obso.product_cpe,
                "responsable": None,
                "version": "",
                "type": "",
                "fournisseur": ""
            }

        notifs.append(obso_dict)
    return jsonify(notifs)



@app.route('/obso-list-cert-api', methods=['GET'])
@cross_origin()
@jwt_required()
def get_obso_list():
    obso = m.Obso_exist.query.all()
    obso_list = []
    for i in obso:
        dict_obso = {}
        obsolete = m.Obsolescence.query.filter_by(id=i.id_obso).first()
        dict_obso['eol'] = obsolete.eol
        dict_obso['version'] = obsolete.version
        dict_obso['name'] = obsolete.product_cpe
        dict_obso['id'] = i.id
        dict_obso['id_cpe'] = i.id_cpe
        dict_obso['id_obso'] = i.id_obso
        obso_list.append(dict_obso)
    return jsonify(obso_list)

@app.route('/detail-obso-cert-api/<id_obso>', methods=["GET"])
@cross_origin()
@jwt_required()
def detail_obso(id_obso):
    obso = m.Obso_exist.query.filter_by(id=id_obso).first()
    dict_obso = {}
    if obso is None:
        return jsonify({'error': 'Obsolete certificate not found.'}), 404
    obsolete = m.Obsolescence.query.filter_by(id=obso.id_obso).first()
    product = m.Client_cpe.query.filter_by(id_cpe=obso.id_cpe).first()
    if product is None:
        return jsonify({'error': 'Product not found.'}), 404
    asset_usage = m.db.session.query(m.Asset_usage).join(m.Client_cpe).filter_by(id_cpe=obso.id_cpe).first()
    if asset_usage is None:
        return jsonify({'error': 'Asset usage not found.'}), 404
    asset = m.Asset.query.filter_by(id=asset_usage.asset_id).first()
    if asset is None:
        return jsonify({'error': 'Asset not found.'}), 404
    service= m.Service.query.filter_by(id= asset.service).first()
    user = m.User.query.filter_by(id= service.manager).first()
    if user is None:
        return jsonify({'eror':'user not found'})
    dict_obso['eol'] = obsolete.eol
    dict_obso['version'] = obsolete.version
    dict_obso['name'] = obsolete.product_cpe
    dict_obso['asset_ref'] = asset.asset_ref
    dict_obso['producer'] = product.producer
    dict_obso['service'] = service.name
    dict_obso['manager'] = user.username
    dict_obso['type'] = product.type
    dict_obso['support'] = obsolete.support
    dict_obso['realeaseDate'] = obsolete.releaseDate
    dict_obso['latest'] = obsolete.latest
    return jsonify(dict_obso)


###################### Rafik ##################"


@app.route('/forgot-password/send-email', methods=['POST'])
# @login_required
@cross_origin()
def send_token_to_email():
    """ Send the reset password token to the user if email is valid """

    input_email = request.json.get('email')

    user = m.User.query.filter_by(email=input_email).first_or_404()
    generated_token = str(uuid.uuid4())
    token = m.reset_password_token(user_id=user.id, token=generated_token)
    db.session.add(token)
    db.session.commit()

    base_url = "http://localhost:3000/brightwatch-demo/user-pages/reset-password/?token="  # asma badalllniiiiiiiiiiiii !!!!!!!!!!!!!!!!!!!!!!!!!
    sender = "pgv.brightway@gmail.com"
    content = base_url + generated_token
    html = f"""\
        <html>
        <body>
        <p>
            Bonjour,
            <br>
            <br>
            <p>Veuillez cliquer <a target="_blank" href="{content}">ici</a> pour finaliser le changement.</p>
            <br>
            <br>
        <p>
            Cordialement,
            <br>
            Equipe Brightwatch
            <br>
            <br>

        </p>

        </body>
        </html>
        """.format(content=content)
    message = MIMEMultipart("alternative")
    subject = "Brightwatch | R�initialiser Votre Mot de Passe."
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = input_email
    part = MIMEText(html, _subtype="html")
    message.attach(part)
    published_on = send_mime_mail(input_email, message)

    return jsonify({"message": "message envoy� avec succ�s"})

@app.route('/lost-otp/send-email', methods=['POST'])
# @login_required
@cross_origin()
def send_token_otp_to_email():
    """ Send the reset password token to the user if email is valid """

    input_email = request.json.get('email')

    user = m.User.query.filter_by(email=input_email).first_or_404()
    generated_token = str(uuid.uuid4())
    token = m.reset_password_token(user_id=user.id, token=generated_token)
    db.session.add(token)
    db.session.commit()

    base_url = "http://localhost:3000/brightwatch-demo/user-pages/reset-otp/?token="
    sender = "pgv.brightway@gmail.com"
    content = base_url + generated_token
    html = f"""\
        <html>
        <body>
        <p>
            Bonjour,
            <br>
            <br>
            <p>Veuillez cliquer <a target="_blank" href="{content}">ici</a> pour finaliser le changement.</p>
            <br>
            <br>
        <p>
            Cordialement,
            <br>
            Equipe Brightwatch
            <br>
            <br>

        </p>

        </body>
        </html>
        """.format(content=content)
    message = MIMEMultipart("alternative")
    subject = "Brightwatch | R�initialiser Votre OTP"
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = input_email
    part = MIMEText(html, _subtype="html")
    message.attach(part)
    published_on = send_mime_mail(input_email, message)

    return jsonify({"message": "message envoy� avec succ�s"})


@app.route('/forgot-password/reset-password', methods=['POST'])
# @login_required
@cross_origin()
def reset_forgotten_password():
    """ Test token and reset password """
    input_token = request.json.get('token')
    input_password = request.json.get('password')
    token = m.reset_password_token.query.filter_by(token=input_token).first_or_404()
    EXPIRATION_DELTA_TIME = datetime.timedelta(days=1)
    token_delta_time = dti.datetime.now() - token.expiration_date
    if token_delta_time > EXPIRATION_DELTA_TIME:
        return jsonify({"message": "token expired"}), 401
    user_id = token.user_id
    user = m.User.query.filter_by(id=user_id).first_or_404()
    user.set_password(input_password)
    db.session.add(user)
    db.session.delete(token)
    db.session.commit()
    return jsonify({"message": "Votre mot de passe � �t� chang� avec succ�s"})

@app.route('/lost-otp/reset-otp', methods=['POST'])
# @login_required
@cross_origin()
def reset_lost_otp():
    """ Test token and reset password """
    input_token = request.json.get('token')
    print("token: !!!", input_token)
    token = m.reset_password_token.query.filter_by(token=input_token).first_or_404()
    print("token obj: !!!", token)
    #EXPIRATION_DELTA_TIME = datetime.timedelta(days=1)
    #token_delta_time = dti.datetime.now() - token.expiration_date
    #if token_delta_time > EXPIRATION_DELTA_TIME:
    #    return jsonify({"message": "token expired"}), 401
    user_id = token.user_id
    user = m.User.query.filter_by(id=user_id).first_or_404()
    print("user obj: !!!", user)
    user.first_login = 0
    db.session.add(user)
    db.session.delete(token)
    db.session.commit()
    return jsonify({"message": "Votre otp a ete reenitialisee"})


@app.route("/qr-2fa", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def qr_2fa():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    secret = user.secret_2fa
    first_login = user.first_login

    if not first_login:
        return jsonify({"first_login": first_login, "secret": secret, "email": user.email})
    else:
        return {}, 401


@app.route("/notifications", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def notification():
    current_user_id = get_jwt_identity()
    user = m.User.query.filter_by(id=current_user_id).first_or_404()

    last_tickets = db.session.query(m.Ticket_notification).filter(
        m.Ticket_notification.manager == current_user_id).order_by(desc(m.Ticket_notification.created_at))[:5]
    result = []

    for ticket in last_tickets:
        if ticket.status == -1:
            status = "Ferm�"
        elif ticket.status == 0:
            status = "En attente"
        elif ticket.status == 1:
            status = "En cours de traitement"
        else:
            status = "Trait�"

        item = {}
        item["ticket_id"] = ticket.ticket_id
        item["id"] = ticket.id
        item["status"] = status
        item["responsable"] = ticket.responsable
        item["manager"] = ticket.manager
        item["created_at"] = dti.datetime.strptime(ticket.created_at, "%Y-%m-%d %H:%M:%S.%f").strftime(
            "%m/%d/%Y, %H:%M:%S")
        result.append(item)

    return jsonify(result)


@app.route('/liste-collab', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@jwt_required()
def list_collab_api():
    current_user_id = get_jwt_identity()

    user = m.User.query.filter_by(id=current_user_id).first_or_404()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    collabs = m.User.query.filter_by(groupe=client_group.id).all()
    liste_collab = []
    for element in collabs:
        dict_collab = {}
        dict_collab['id'] = element.id
        dict_collab['username'] = element.username
        dict_collab['phone'] = element.phone
        dict_collab['email'] = element.email
        if element.role == 's_user':
            dict_collab['role'] = 'Collaborateur'
        elif element.role == 'ad_user':
            dict_collab['role'] = 'Admin'
        else:
            dict_collab['role'] = 'autre'

        liste_collab.append(dict_collab)

    return jsonify(liste_collab)

##### get assets from wazhu ############
@app.route("/assets-agent", methods=["GET"])
@cross_origin(headers=["Content-Type"])
def get_assets_from_agents():
    get_token_endpoint = "https://16.170.143.177:55000/security/user/authenticate?raw=true"
    all_agents_endpoint = "https://16.170.143.177:55000/agents?pretty=true"
    response = requests.get(get_token_endpoint, auth=("wazuh","wazuh"), verify=False)
    if response.status_code == 200:
        token = response.text
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response_agents = requests.get(all_agents_endpoint, headers=headers, verify=False)
        if response_agents.status_code == 200:
            agents = response_agents.json()["data"]["affected_items"]
            agents_id_list = []
            for agent in agents:
                agents_id_list.append({"id":agent["id"], "name":agent["name"]})

        print("agents:!!!! ", agents_id_list)

        all_data = []
        admin_user = m.User.query.filter_by(role="ad_user").first_or_404()
        client = m.Client_group.query.filter_by(id=admin_user.groupe).first_or_404()

        for agent in agents_id_list:
            single_agent_endpoint = f"https://16.170.143.177:55000/syscollector/{agent['id']}/packages?pretty=true&limit=10000"
            response = requests.get(single_agent_endpoint, headers=headers, verify=False)
            if response.status_code == 200:
                data = response.json()["data"]["affected_items"]
                for item in data:
                    actif = agent["name"]
                    if "vendor" in item:
                        vendor = item["vendor"]
                    else:
                        vendor = ""
                    #vendor = "vendor test"
                    #vendor = re.sub(r'<.*?>','',item["vendor"]).strip()
                    # version=item["version"]
                    product = item["name"]
                    #version = ""
                    #version_split=item["version"].split(".")
                    #for element in version_split:
                    #    try:
                    #        int(element)
                    #        version += element + "."
                    #    except ValueError:
                    #        break
                    #version = version[:-1]
                    version=item["version"]
                    all_data.append({"actif":actif, "type":"application", "vendor":vendor, "product":product, "version":version, "manager" : "client_demo", "responsable" : "client_demo", "service":"wazuh", "importance":3})
                    
        df = pd.DataFrame(all_data)
        df_test = df.head(8)
        #file_path = os.path.join(app.config['UPLOAD_FOLDER'], "agents_data.csv")
        file_path_test = os.path.join(app.config['UPLOAD_FOLDER'], "agents_data_test.csv")
        #df.to_csv(file_path, index=False)
        df_test.to_csv(file_path_test, index=False)
        
        import_results = client.import_assets(file_path_test, 10000)

        return jsonify({'msg': 'success'})

@app.route("/test-api", methods=["GET"])
@cross_origin(headers=["Content-Type"])
def test_api():
    return jsonify({'msg': 'success'})

@app.route("/upgrade-subscription/", methods=["POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
#@cross_origin(headers=["Content-Type"])
@jwt_required()
def upgrade_subscription():
    aws_premium_url = 'https://license.loadbalancerbw.click/check-premium-license'
    premium_license = request.json.get("premium_license")
    email = request.json.get("email")
    data = {
        "email":email,
        "premium_license": premium_license
    }
    response = requests.post(aws_premium_url, data=data)
    json_content = response.json()
    if response.status_code == 200:
        print("upgrade successful !")
        current_user_id = get_jwt_identity()
        user = m.User.query.filter_by(id=current_user_id).first_or_404()
        client = m.Client_group.query.filter_by(id=user.groupe).first_or_404()
        subscription = m.Subscription.query.filter_by(id=client.subscription).first_or_404()
        subscription.type = 2
        db.session.add(subscription)
        db.session.commit()
        print("subscription type: !!!", subscription.type)

    return json_content

@app.route("/security-agent/authenticate", methods=["POST"])
@cross_origin(headers=["Content-Type"])
def agent_authenticate():
    username = request.json.get("username")
    password = request.json.get("password")
    actif_name = request.json.get("actif_name")
    agent = m.Compte_technique.query.filter_by(username=username).first_or_404()
    if agent:
        if agent.password == password:
            print("the agent is correct !!")
            token = secrets.token_urlsafe(50)
            agent_actif = m.Agents_tokens.query.filter_by(actif_name=actif_name).first()
            if agent_actif:
                agent_actif.token = token
                db.session.add(agent_actif)
                db.session.commit()
            else:
                print("agent wasn't found in agents_tokens table !!!")
                agent = m.Agents_tokens(actif_name=actif_name, token=token)
                db.session.add(agent)
                db.session.commit()
            return jsonify({'token': token})
        return jsonify({'msg': 'wrong password'})
    return jsonify({'msg': 'no agent detected'})

@app.route("/security-agent/import_csv", methods=["POST"])
#@cross_origin(headers=["Content-Type"])
def import_csv():
    request_data = request.get_json()
    actif_name = request_data["actif_name"]
    token = request_data["token"]
    csv_data = request_data["csv_data"]
    print("csv_data received !!!!!!!!!!", csv_data)
    agent_actif = m.Agents_tokens.query.filter_by(actif_name=actif_name, token=token).first()
    if agent_actif:
        print("the agent is secure !!!")
        return jsonify({'msg': 'the agent is secure !!!'})
    else:
        print("the agent is not secure !!!")
        return jsonify({'msg': 'the agent is not secure !!!'})


@app.route("/security-agent/import_csv2", methods=["POST"])
def import_csv2():
    #request_data = request.get_json()
    #print("request data: !!!!", request_data)
    #actif_name = request_data["actif_name"]
    #token = request_data["token"]
    #csv_data = request_data["csv_data"][0]
    #print("csv_data: !!!!", csv_data)
    #print("actif_name: !!!!", actif_name)
    #print("token: !!!!", token)
    #data = {'actif_name': 'BRL017', 'token': 'Qj7wbtQIZA_yp7UIKwCzG-teJ5_f1liBDMhBwrzgBfV4QRutsTJ2_TQG0pLrGI-UBUg', 'csv_data': '[    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X86 Additional Runtime - 14.32.31326",        "Vendor":  "Microsoft Corporation",        "Version":  "14.32.31326"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532",        "Vendor":  "Microsoft Corporation",        "Version":  "14.36.32532"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Update Health Tools",        "Vendor":  "Microsoft Corporation",        "Version":  "3.74.0.0"    },    {        "Node":  "BRL017",        "Name":  "VMware Tools",        "Vendor":  "VMware",        "Version":  "12.1.0.20219665"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532",        "Vendor":  "Microsoft Corporation",        "Version":  "14.36.32532"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.32.31326",        "Vendor":  "Microsoft Corporation",        "Version":  "14.32.31326"    }]'}
    data = {'actif_name': 'BRL017', 'token': 'Qj7wbtQIZA_yp7UIKwCzG-teJ5_f1liBDMhBwrzgBfV4QRutsTJ2_TQG0pLrGI-UBUg',
            'csv_data': '[    {        "Node":  "BRL017",        "Name":  "product1",        "Vendor":  "vendor1",        "Version":  "1.0.1"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532",        "Vendor":  "Microsoft Corporation",        "Version":  "15.0.1"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Update Health Tools",        "Vendor":  "Microsoft Corporation",        "Version":  "3.74.0.0"    },    {        "Node":  "BRL017",        "Name":  "VMware Tools",        "Vendor":  "VMware",        "Version":  "12.1.0.20219665"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532",        "Vendor":  "Microsoft Corporation",        "Version":  "14.36.32532"    },    {        "Node":  "BRL017",        "Name":  "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.32.31326",        "Vendor":  "Microsoft Corporation",        "Version":  "14.32.31326"    }]'}
    data_file_path = os.path.join(app.config['UPLOAD_FOLDER'], "data.csv")

    actif = data["actif_name"]
    token= data["token"]
    csv_data = data["csv_data"]
    csv_data = ast.literal_eval(csv_data)
    all_data = []
    for item in csv_data:
        vendor = item["Vendor"]
        product = re.sub(r' - .+$', '', item["Name"])
        version = item["Version"]
        admin_user = m.User.query.filter_by(role="ad_user").first()
        client = m.Client_group.query.filter_by(id=admin_user.groupe).first_or_404()
        all_data.append(
            {"actif": "BRL031", "type": "application", "vendor": vendor, "product": product, "version": version,
             "manager": admin_user.username, "responsable": admin_user.username, "service": "base", "importance": 3})
    df = pd.DataFrame(all_data)
    df_test = df.head(8)
    file_path_test = os.path.join(app.config['UPLOAD_FOLDER'], "agents_data_test.csv")
    file_path_test2 = os.path.join(app.config['UPLOAD_FOLDER'], "added_rows.csv")
    #df_test.to_csv(file_path_test, index=False)
    #import_results = client.import_assets(file_path_test, 10000)
    df_old = pd.read_csv(file_path_test)

    ####### creating csv file to import in db #####
    merged_df1 = pd.merge(df_test, df_old, on='product', how='left', indicator=True)
    added_rows = merged_df1[merged_df1['_merge'] == 'left_only']
    added_rows = added_rows.drop(columns=['_merge'])
    columns_to_drop = added_rows.filter(like='_y').columns
    added_rows = added_rows.drop(columns=columns_to_drop)
    added_rows.columns = df_old.columns
    added_rows.to_csv(file_path_test2, index=False)

    ###### get list of deleted products #####
    merged_df2 = pd.merge(df_old, df_test, on='product', how='left', indicator=True)
    deleted_rows = merged_df2[merged_df2['_merge'] == 'left_only']
    deleted_rows = deleted_rows.drop(columns=['_merge'])
    columns_to_drop2 = deleted_rows.filter(like='_y').columns
    deleted_rows = deleted_rows.drop(columns=columns_to_drop2)
    deleted_rows.columns = df_old.columns

    deleted_records = deleted_rows.to_dict(orient="records")
    deleted_cpes = []
    for item in deleted_records:
        asset = m.Asset.query.filter_by(asset_ref=item["actif"]).first()
        product = re.sub(r' - .+$', '', item["product"])
        product_formated = product.lower().replace(" ","_")
        cpe = m.Client_cpe.query.filter_by(name=product_formated, version=item["version"]).first()
        print("product name: !!!", re.sub(r' - .+$', '', item["product"]))
        asset_prod = m.Asset_usage.query.filter_by(asset_id=asset.id, cpe=cpe.id_cpe).first()
        if asset_prod:
            db.session.delete(asset_prod)
            db.session.commit()
            print(f"Instance with asset_prod {asset_prod.id} deleted.")

    #### get list of updated products #####
    merged_df3 = pd.merge(df_test, df_old, on='product', how='inner', suffixes=('_new', '_old'))
    updated_rows = merged_df3[merged_df3['version_new'] != merged_df3['version_old']]
    columns_to_drop3 = updated_rows.filter(like='_old').columns
    updated_rows = updated_rows.drop(columns=columns_to_drop3)
    updated_rows.columns = df_old.columns
    updated_records = updated_rows.to_dict(orient="records")

    print("updated_rows: !!!", updated_records)

    #client.update_products(deleted_cpes, actif)

    return jsonify({'msg':'success !!!'})




