""" This module contains all the routes of the application. This routes link URLs withe the associated view functions (handlers) """
import csv
import uuid
import pandas as pd
from flask import render_template, flash, redirect, url_for, request, session, jsonify, abort
from flask_cors import cross_origin
from flask_restx.cors import crossdomain
from flask import Response
from API.flask_app import app, db
from database.client import get_clients, get_clients_info, get_analysts
from API.flask_app import forms as f
from flask_login import current_user, login_user, logout_user, login_required
from API.flask_app import models as m
from API.flask_app.models import requires_roles, owner_required
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from API.authy.utils import create_user, send_authy_token_request, verify_authy_token
from authy import AuthyApiException
from API.flask_app.decorators import verify_authy_request, login_verified
from datetime import datetime
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
    cve = request.json.get("cve")
    print("cve", cve)
    if not cve or (any(c in special_characters for c in cve)):
        print("cve", cve)
        print("le champ cve est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ cve est obligatoire ou ne doit pas contenir de caractères spéciaux"})

    action = request.json.get("action")
    print("action", action)
    if not action or (any(c in special_characters for c in action)):
        print("action", action)
        print("le champ action est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ action est obligatoire ou ne doit pas contenir de caractères spéciaux"})
    comment = request.json.get("comment")
    print("comment", comment)
    if not comment or (any(c in special_characters for c in comment)):
        print("comment", comment)
        print("le champ comment est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ comment est obligatoire ou ne doit pas contenir de caractères spéciaux"})

    title = request.json.get("title")
    print("title", title)
    if not title or (any(c in special_characters for c in title)):
        print("title", title)
        print("le champ title est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ title est obligatoire ou ne doit pas contenir de caractères spéciaux"})
    description = request.json.get("description")
    print("descr", description)
    if not description or (any(c in special_characters for c in description)):
        print("descr", description)
        print("le champ description est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify(
            {"erreur": "le champ description est obligatoire ou ne doit pas contenir de caractères spéciaux"})
    cvss = request.json.get("cvss")
    print("cvss", cvss)
    print("cve", cve, "title", title, "description", description, "cvss", cvss)
    cve_tmp = m.Cve_temp(id=cve, title=title,
                         description=description, cvss2=float(cvss))
    db.session.add(cve_tmp)
    db.session.commit()

    asset_instance = m.Asset.query.filter_by(asset_ref=asset).first_or_404()
    asset_usage = m.Asset_usage.query.filter_by(cpe=cpe, asset_id=asset_instance.id).first_or_404()
    print('imp', asset_instance.importance, 'cvss', cvss)
    score = (float(cvss) * float(asset_instance.importance)) / 3
    created_at = datetime.datetime.now()
    ticket = m.Ticket(usage_id=asset_usage.id, cve=cve_tmp.id, created_at=created_at, score=float(score), action=action,
                      comment=comment, manager=user.id)
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
        print("le champ cve est obligatoire ou ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ cve est obligatoire ou ne doit pas contenir de caractères spéciaux"})

    action = request.json.get("action")
    print("action", action)
    if any(c in special_characters for c in action):
        print("action", action)
        print("le champ action ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ action ne doit pas contenir de caractères spéciaux"})
    comment = request.json.get("comment")
    print("comment", comment)
    if any(c in special_characters for c in comment):
        print("comment", comment)
        print("le champ comment ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ comment  ne doit pas contenir de caractères spéciaux"})
    info = request.json.get("info")
    print("info", info)
    if any(c in special_characters for c in info):
        print("info", info)
        print("le champ info ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ info ne doit pas contenir de caractères spéciaux"})
    due_date = request.json.get("due_date")
    print("due_date", due_date)

    title = request.json.get("title")
    print("title", title)
    if any(c in special_characters for c in title):
        print("title", title)
        print("le champ title ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ title ne doit pas contenir de caractères spéciaux"})
    description = request.json.get("description")
    print("descr", description)
    if any(c in special_characters for c in description):
        print("descr", description)
        print("le champ description  ne doit pas contenir de caractères spéciaux")
        return jsonify({"erreur": "le champ description ne doit pas contenir de caractères spéciaux"})
    cvss = request.json.get("cvss")
    print("cvss", cvss)
    print("cve", cve, "title", title, "description", description, "cvss", cvss)

    cve_tmp = m.Cve_temp(id=cve, title=title,
                         description=description, cvss2=float(cvss))
    db.session.add(cve_tmp)
    db.session.commit()
    created_at = datetime.datetime.now()

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
        assets = m.Asset.query.filter_by(manager=user.id).all()
        client_group = m.Client_group.query.filter_by(id=user.groupe).first()
        service = client_group.get_services()
        nb_assets = len(assets)
        nb_service = len(service)

        unread_tickets = user.get_unread_tickets()
        count_unread_tickets = len(unread_tickets)
        tickets = user.get_tickets()
        company_name = client_group.name
        company_description = client_group.type

        response = {"token": access_token, "user_id": user.id, "username": user.username, "nom": user.nom,
                    "prenom": user.prenom, "role": role, "ass": nb_assets, "service": nb_service,
                    "count": count_unread_tickets, "count_tickets_dash": len(tickets),
                    'email': user.email,
                    'country_code': user.country_code, 'phone': user.phone, 'company': company_name,
                    'company_desc': company_description}
        print('response', response)
        return jsonify(response)
    assets = m.Asset.query.filter_by(responsable=user.id).all()
    client_group = m.Client_group.query.filter_by(id=user.groupe).first()
    nb_assets = len(assets)
    nb_vul = len(m.Cve_temp.query.all())
    unread_tickets = user.get_unread_tickets_team()
    count_unread_tickets = len(unread_tickets)
    tickets = user.get_user_tickets()
    company_name = client_group.name
    company_description = client_group.type
    nb_service = 0
    closed_tickets = user.get_closed_tickets_team()
    non_closed_tickets = len(tickets) - len(closed_tickets)
    asset_list = []
    response = {"token": access_token, "user_id": user.id, "username": user.username, "nom": user.nom,
                "prenom": user.prenom, "role": role, "ass": nb_assets, "service": nb_service,
                "count": count_unread_tickets, "count_tickets_dash": len(tickets), 'email': user.email,
                'country_code': user.country_code, 'phone': user.phone, 'company': company_name,
                'company_desc': company_description, "tickets_traites": len(closed_tickets),
                "tickets_non_traites": non_closed_tickets}
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

        return jsonify({"msg": "authentification réussie"})
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
        liste_1 = []
        for element in services:
            dict1 = {}
            dict1['name'] = element['name']
            dict1['manager'] = element['manager']
            liste_1.append(dict1)
        products = user.get_client_assets()
        infos = client_group.get_subscription_info()

        liste_2 = []
        for element in tickets:
            dict2 = {}
            dict2['cve'] = element['cve']
            dict2['opened_at'] = element['opened_at']
            dict2['closed_at'] = element['closed_at']
            dict2['created_at'] = element['created_at']
            dict2['read'] = element['read']
            dict2['score'] = element['score']
            dict2['status'] = element['status']
            dict2['asset_ref'] = element['asset_ref']
            dict2['cpe'] = element['cpe']
            dict2['description'] = element['description']
            liste_2.append(dict2)

        return jsonify(
            {"username": user.username, 'nom': user.nom, 'prenom': user.prenom, "abonneement": infos['subscription'],
             "date_début": infos['start_at'], "date_exp": infos['expire_on'], "cpe_credits": infos['cpe_credits'],
             'nb_products': len(products), 'nb_actifs': len(assets), 'nb_tickets': len(tickets),
             'nb_services': len(services), 'entreprise': client_group.name, 'entreprise_desc': client_group.type,
             'tickets': liste_2, 'services': liste_1})
    else:
        return jsonify({"error": "you do not have the permission"}), 401


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
            dict_chart1['month'] = datetime.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S').strftime("%B")
            vuls.append(dict_re)
            liste_vuls_chart1.append(dict_chart1)
            liste_vuls_chart.append(dict_chart2)
            liste_vuls_chart3.append(dict_chart3)
            nombre_actif.append(dict_actif)
            if n['closed_at']:
                dict_delta['open'] = datetime.datetime.strptime(n['opened_at'], '%Y-%m-%d %H:%M:%S').strftime("%m")
                dict_delta['close'] = datetime.datetime.strptime(n['closed_at'], '%Y-%m-%d %H:%M:%S').strftime("%m")
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
            month_name = datetime.datetime(1, int(s), 1).strftime("%B")
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
                        return jsonify({"error": "le champ cve ne peut pas accepter les caractères spéciaux"})
                    if (any(c in special_characters for c in description)):
                        return jsonify({"error": "le description cve ne peut pas accepter les caractères spéciaux"})
                    if (any(c in special_characters for c in info)):
                        return jsonify({"error": "le champ info ne peut pas accepter les caractères spéciaux"})
                    if (any(c in special_characters for c in comment)):
                        return jsonify({"error": "le champ comment ne peut pas accepter les caractères spéciaux"})
                    if (any(c in special_characters for c in action)):
                        return jsonify({"error": "le champ action ne peut pas accepter les caractères spéciaux"})
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
                        created_at = datetime.datetime.now()
                        print("created_at", created_at)
                        date_time_obj = datetime.datetime.strptime(deadline, '%d/%m/%y')
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
            for element in liste1:
                usage_instance = m.Asset_usage.query.filter_by(id=element).first_or_404()
                liste2.append(usage_instance.asset_id)
            expectedResult = [d for d in assets if d['id'] in liste2]
            l1 = []
            if expectedResult:
                for element in expectedResult:
                    dict1 = {}
                    if (element['id_cpe']):
                        cpe = m.Client_cpe.query.filter_by(id_cpe=element['id_cpe']).first_or_404()
                        dict1['cpe_readable'] = cpe.get_full_product_name()
                        dict1['producer'] = element['producer']
                        dict1['asset_ref'] = element['asset_ref']
                        l1.append(dict1)
                return jsonify(l1)
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
            for element in liste1:
                usage_instance = m.Asset_usage.query.filter_by(id=element).first_or_404()
                liste2.append(usage_instance.asset_id)
            expectedResult = [d for d in assets if d['id'] in liste2]
            l1 = []
            if expectedResult:
                for element in expectedResult:
                    dict1 = {}
                    if (element['cpe']):
                        cpe = m.Client_cpe.query.filter_by(id_cpe=element['cpe']).first_or_404()
                        dict1['cpe_readable'] = cpe.get_full_product_name()
                        dict1['producer'] = element['producer']
                        dict1['asset_ref'] = element['asset_ref']
                        l1.append(dict1)
                return jsonify(l1)
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
        return jsonify({"success": "asset modifié avec succès"})
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
    if t:
        cpe = m.Client_cpe.query.filter_by(id_cpe=t['cpe']).first_or_404()
        if cpe:
            t['cpe'] = cpe.get_full_product_name()  # convert cpe_id to a name readble by the user
            # convert status int to string status readble by the user
            if t['status'] == -1:
                t['status'] = 'Fermé',
                print('date', datetime.datetime.now())
                t['closed_at'] = datetime.datetime.now()
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
        ticket_hist = m.Ticket_history(ticket_id=ticket_id, status=s)
        ticket.status = s
        if not ticket.opened_at and status == 1:
            now = datetime.datetime.now()
            ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
            ticket_hist.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
        elif s == -1:
            now = datetime.datetime.now()
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
                t['status'] = 'Fermé',
                print('date', datetime.now())
                t['closed_at'] = datetime.now()
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
        ticket.status = s
        ticket.read = 1
        if not ticket.opened_at and status == 1:
            now = datetime.datetime.now()
            ticket.opened_at = now.strftime("%Y-%m-%d %H:%M:%S")
        elif s == -1:
            now = datetime.datetime.now()
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
        flash('Format de fichier non supporté!')
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
                "message": "Vous avez atteint la limite de produits à ajouter"
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
            user_responsable_prenom = ""
            service = m.Service.query.filter_by(id=s['id']).first_or_404()
            if service.responsable:
                user_responsable = m.User.query.filter_by(id=service.responsable).first_or_404()
                user_responsable_prenom = user_responsable.prenom
            service_list.append({'name': s['name'], 'manager': s['manager'], 'responsable': user_responsable_prenom,
                                 'localisation': s['localisation'], 'desciption': s['description'], 'id': s['id']})
    print('service list', service_list)
    return jsonify(service_list)


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
        return jsonify({"error": "Service existe déja"}), 400

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
    flash('Service ajouté avec succès!')
    return jsonify({"success": "Service ajouté avec succès"}), 201


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
                element['cpe_readable'] = cpe.get_full_product_name()
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
    status_str = {0: 'Activé', 1: 'Désactivé'}  # Show the status of the asset as a string (Activé/Désactivé)
    if len(assets) == 0:
        return jsonify({'msg': 'aucun asset trouvé'})
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
            flash('Acif ajouté avec succès!')
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
        return jsonify("asset existe déjà"), 400
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
        flash(f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistrés""")
        flash('Vous avez atteint la limite autorisée de votre abonnement')
        print("Vous avez atteint la limite autorisée de votre abonnement")
        return jsonify({'error': "Vous avez atteint la limite autorisée de votre abonnement"}), 400
    else:
        cpe = m.Client_cpe()
        type = request.json.get('type')
        producer = request.json.get('producer')
        type = "a"
        if type == "os":
            type = "o"

        if any(c in special_characters for c in producer):
            print("le fournisseur ne peut pas contenir de caractères spéciaux")
            return jsonify({'error': "le fournisseur ne peut pas contenir de caractères spéciaux"}), 201

        producer = normalise_cpe_name(producer)
        name = request.json.get('name')
        if any(c in special_characters for c in name):
            print("le nom ne peut pas contenir de caractères spéciaux")
            return jsonify({'error': "le nom ne peut pas contenir de caractères spéciaux"}), 201
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
            return jsonify({'success': "Produit Crée avec succès"}), 201

        else:
            return jsonify({'error': "Produit existe déjà"}), 400


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
        return jsonify({'success': "Suppression effectuée avec succès"}), 201


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
                    flash('Format de fichier non supporté!')
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
                    flash(f'''{import_results['nb_assets']}  acifs ont été trouvé dans le fichier''')
                    flash(f'''{import_results['assets']} nouveaux acifs ont été ajoutés!''')
                    flash(f'''{import_results['nb_cpes']} produits ont été trouvés dans le fichier!''')
                    flash(f'''{import_results['cpes']} nouveaux produits ont été ajoutés!''')
                    if import_results['nb_cpes'] != import_results['cpes']:
                        flash(f'''{import_results['duplicated_cpes']} produits sont dupliqués!''')
                    if import_results['cpe_credits'] == 0:
                        flash(f'''Vous avez atteint la limite de produits à ajouter''')
                    client_info = client.get_all_info()  # Getting product credits information after the import
                    flash(
                        f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistrés""")
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
                flash(f"""Vous avez {client_info['nb_products']}/{client_info['cpe_credits']} produits enregistré""")
                flash('Vous avez atteint la limite autorisé de votre abonnement')
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
                    flash('Profuit ajouté avec succès!')
                    """ Save logs """
                    msg = f""" {current_user.username} added new product to {asset.asset_ref}"""
                    debug_log('info', msg)
                    return redirect(url_for('add_product'))
                else:
                    flash('Ce profuit existe dèjà dans l\'actif!')

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
                flash('Profuit introuvable! Veillez vérifier votre saisie')
                return redirect(url_for('del_product'))
            else:
                db.session.delete(a_u)
                db.session.commit()
                flash('Produit Supprimé de l\'actif ', form.asset_ref.data)
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
                    t['status'] = 'Fermé'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Traité'
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
                t['status'] = 'Fermé'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'Pris en compte'
            elif t['status'] == 2:
                t['status'] = 'Traité'
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
                    t['status'] = 'Fermé'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Traité'
            if len(tickets) == 0:
                flash('Aucun ticket n\'a été trouvé!')
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
                    t['status'] = 'Fermé'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Traité'
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
                flash('Ticket modifié avec succès!')
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
                    t['status'] = 'Fermé'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Traité'

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
                t['status'] = 'Fermé'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Traité'
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
                t['status'] = 'Fermé'
            elif t['status'] == 0:
                t['status'] = 'En attente'
            elif t['status'] == 1:
                t['status'] = 'En cours de traitement'
            elif t['status'] == 2:
                t['status'] = 'Traité'
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
            flash('Votre compte n\'est pas activé!')
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
            flash('Votre compte n\'est pas activé!')
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
    flash("Vous êtes maintenant déconnecté!", 'info')
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
        flash('Utilisateur ajouté avec succès!')
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
                     'ad_user': 'Admin'}  # Show the status of the asset as a string (Activé/Désactivé)
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
                flash('Mot de passe modifié avec succès!')
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
        status = {2: 'Expiré', 1: 'Activé', 0: 'Désactivé'}
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
            flash('Client ajouté avec succès!')
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
            flash('Clientf Supprimé avec succès!')
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
            alerts_str = {1: 'Activé', 0: 'Désactivé'}
            if form.validate_on_submit():
                if form.name.data:
                    client.name = form.name.data
                if form.type.data:
                    client.type = form.type.data
                if form.alerts.data:
                    client.alerts = form.alerts.data
                db.session.commit()
                flash('Client modifié avec succès!')
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
        status_str = {1: 'Activé', 0: 'Désactivé',
                      -1: 'Supprimé'}  # Show the status of the user as a string (Activé/Désactivé/Supprimé)
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
        flash('Analyste ajouté avec succès!')
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
                    t['status'] = 'Annulé'
                elif t['status'] == 0:
                    t['status'] = 'En attente'
                elif t['status'] == 1:
                    t['status'] = 'Pris en compte'
                elif t['status'] == 2:
                    t['status'] = 'Validé'
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
                    pt['status'] = 'Annulé'
                elif pt['status'] == 0:
                    pt['status'] = 'En attente'
                elif pt['status'] == 1:
                    pt['status'] = 'En cours d\'analyse'
                elif pt['status'] == 2:
                    pt['status'] = 'Validé'
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
                    flash('ticket traité!')
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
                    flash('ticket validé!')
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
        status_str = {1: 'Activé', 0: 'Désactivé',
                      -1: 'Supprimé'}  # Show the status of the user as a string (Activé/Désactivé/Supprimé)
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
            status_str = {1: 'Activé', 0: 'Désactivé',
                          -1: 'Supprimé'}  # Show the status of the user as a string (Activé/Désactivé/Supprimé)
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
                flash('Utilisateur modifié avec succès!')
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
            flash(f"""Le compte de {user.username} a été supprimé!""")
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
#             flash(f"""Le compte de {user.username} a été désactivé!""")
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
            flash('Plan d\'abonnement ajouté avec succès!')
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
                flash('Abonnement modifié avec succès!')
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
            flash('Abonnement supprimé avec succès!')
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
            flash(f""" {client.name} est souscrit à l\'subscription{plan.name} avec succès!""")
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
        status = {2: 'Expiré', 1: 'Activé', 0: 'Désactivé'}
        if form.validate_on_submit():
            # elif form.action.data == 'Changer':
            subscription.type = form.plan.data
            subscription.start_at = form.start_at.data
            subscription.expire_on = form.expire_on.data
            subscription.status = 1
            db.session.commit()
            flash('Abonnement modifié avec succès!')
            """ Save logs """
            msg = f""" {current_user.username} changed subscription of {subscription.client.name}"""
            debug_log('info', msg)
            # elif form.action.data == 'Désactiver': # put the status to 0 and expire_on to the expiry's day date
            #     subscription.status = 0
            #     now = datetime.now()
            #     subscription.expire_on = now.strftime("%Y-%m-%d %H:%M:%S")
            #     db.session.commit()
            #     flash('Abonnement désactivé pour le client ',subscription.client.id)
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
        status = {2: 'Expiré', 1: 'Activé', 0: 'Désactivé'}
        if form.validate_on_submit():
            subscription.status = 1
            expire_date = datetime.combine(form.expire_on.data, datetime.min.time())
            if subscription.expire_on < expire_date:
                subscription.expire_on = expire_date
                db.session.commit()
                flash('Abonnement prolongé avec succès!')
                """ Save logs """
                msg = f""" {current_user.username} extended subscription of {subscription.client.name} to {subscription.expire_on}"""
                debug_log('info', msg)
                return redirect(url_for('list_clients'))
            else:
                flash('L\'Abonnement n\'a pas été prolongé!')
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
        status = {2: 'Expiré', 1: 'Activé', 0: 'Désactivé', -1: 'Désactivé'}
        if form.validate_on_submit():
            if form.action.data == 'disable':
                subscription.status = 0
                now = datetime.now()
                subscription.expire_on = now.strftime("%Y-%m-%d %H:%M:%S")
                db.session.commit()
                flash(f"""Abonnement désactivé pour {subscription.client.name}""")
                """ Save logs """
                msg = f""" {current_user.username} disabled subscription of {subscription.client.name}"""
                debug_log('info', msg)
            elif form.action.data == 'cancel':
                db.session.delete(subscription)
                db.session.commit()
                flash(f"""Abonnement annulé pour {subscription.client.name}""")
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
        status = {2: 'Expiré', 1: 'Activé', 0: 'Désactivé'}
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
            flash('Autorisation confirmé!')
            return redirect(url_for('index'))
        elif user.authy_status == 'denied':
            flash('Autorisation refusé!')
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
    non_closed_tickets = 0
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
                dict_tickets_trend['created_at'] = datetime.datetime.strptime(element['created_at'],
                                                                              '%Y-%m-%d %H:%M:%S').month
                liste_tickets_by_trend.append(dict_tickets_trend)

            liste_vuls_chart2 = sorted(liste_tickets_by_trend, key=itemgetter('created_at'))
            outputList1_tickets_trend = []

            for n, k in groupby(liste_vuls_chart2, key=itemgetter("created_at")):
                outputList1_tickets_trend.append(list(k))
            for element in outputList1_tickets_trend:
                for e in element:
                    month_number = e['created_at']
                    datetime_object = datetime.datetime.strptime(str(month_number), "%m")
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
                datetime_object = datetime.datetime.strptime(str(month_number), "%m")
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
        liste_collab.append(dict_collab)

    return jsonify(liste_collab)


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
                  Vous êtes inscrit(e) au service Brightwatch.
                  <br>
                 De nouveaux tickets vous ont été affectés; vous êtes invité(e) à vous connecter à votre Tableau de bord pour en prendre connaissance.
              <br>
              <br>
              <p>
              Cordialement,
              <br>
              Votre équipe Brightwatch
              <br>
              <br>
              N.B: ceci est un message automatique, merci de ne pas y répondre.
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
        tickets_23 = sorted(tickets, key=itemgetter('cve'))
        for n, k in groupby(tickets_23, key=itemgetter("cve")):
            list_cves_len.append(list(k))
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
            dict_chart1['month'] = datetime.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S').strftime("%B")
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

        vuls_2 = sorted(vuls, key=itemgetter('cve'))
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
            dict_delta['open'] = datetime.datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S')
            dict_delta['close'] = datetime.datetime.strptime(n['closed_at'], '%Y-%m-%d %H:%M:%S')
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
        month_name = datetime.datetime(1, int(s), 1).strftime("%B")
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
        alerts = m.Aut_alert.query.all()
        list_alerts = []
        now = datetime.datetime.now()
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
    sender_email = 'pgv.brightway@gmail.com'
    receiver = 'asma.sehli.96@gmail.com'
    input_name = request.json.get('name')
    input_email = request.json.get('email')
    input_message = request.json.get('subject')
    text = input_message
    text2 = input_email
    print('text', text)

    message = MIMEMultipart("alternative")
    subject = "Msg recu de contact support du user " + user.nom + str(user.id)
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(text2, "plain")
    message.attach(part1)

    published_on = send_mime_mail(receiver, message)

    return jsonify({"message": "message envoyé avec succès"})


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

        if histories:
            for element in histories:
                dict_hist = {}
                dict_hist['id'] = element.id
                dict_hist['title'] = element.opened_at
                dict_hist['cardDetailedText'] = element.comment
                dict_hist['cardSubtitle'] = element.action
                dict_hist['cardTitle'] = element.status
                ticket_hist_list.append(dict_hist)

    return jsonify(ticket_hist_list)


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


@app.route("/list-services-cert", methods=["GET"])
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

@app.route("/list-client-groups-cert", methods=["GET"])
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
        else :
            dict_client['subscription'] = ""
        list_clients.append(dict_client)
    return jsonify(list_clients)


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
        role_value  = "ad_user"
    else :
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
    subscription = m.Subscription(type=sub_plan.id, start_at=datetime.datetime.now(),
                                  expire_on=datetime.datetime.now()+datetime.timedelta(months = 24))
    subscription.client = client_group
    db.session.add(subscription)
    db.session.commit()
    return jsonify({"message": "client added sccessfully"}), 201



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


@app.route("/client-detail-api", methods=["GET"])
@cross_origin()
@jwt_required()
def client_detail_api():
    client_id = request.json.get('client_id')
    client_group = m.Client_group.query.filter_by(id=int('client_id')).first_or_404()
    subs_plans = m.Subs_plan.query.all()
    client_dict = {}
    client_dict['name'] = client_group.name
    client_dict['type'] = client_group.type
    sub = m.Subscription.query.filter_by(id=client_group.subscription).first_or_404()
    abon = m.Subs_plan.query.filter_by(id=sub.type).first_or_404()
    client_dict['subscription'] = abon.name
    client_dict['id'] = client_group.id
    return jsonify(client_dict)


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
        flash('Format de fichier non supporté!')
    else:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        client = m.Client_group.query.filter_by(id=8).first()
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
                "message": "Vous avez atteint la limite de produits à ajouter"
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
    subject = "Brightwatch | Réinitialiser Votre Mot de Passe."
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = input_email
    part = MIMEText(html, _subtype="html")
    message.attach(part)
    published_on = send_mime_mail(input_email, message)

    return jsonify({"message": "message envoyé avec succès"})


@app.route('/forgot-password/reset-password', methods=['POST'])
# @login_required
@cross_origin()
def reset_forgotten_password():
    """ Test token and reset password """
    input_token = request.json.get('token')
    input_password = request.json.get('password')
    token = m.reset_password_token.query.filter_by(token=input_token).first_or_404()
    EXPIRATION_DELTA_TIME = datetime.timedelta(days=1)
    token_delta_time = datetime.datetime.now() - token.expiration_date
    if token_delta_time > EXPIRATION_DELTA_TIME:
        return jsonify({"message": "token expired"}), 401
    user_id = token.user_id
    user = m.User.query.filter_by(id=user_id).first_or_404()
    user.set_password(input_password)
    db.session.add(user)
    db.session.delete(token)
    db.session.commit()
    return jsonify({"message": "Votre mot de passe à été changé avec succès"})


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
        m.Ticket_notification.manager==current_user_id).order_by(desc(m.Ticket_notification.created_at))[:5]
    result = []

    for ticket in last_tickets:
        if ticket.status == -1:
            status = "Fermé"
        elif ticket.status==0:
            status = "En attente"
        elif ticket.status == 1:
            status = "En cours de traitement"
        else:
            status = "Traité"

        item = {}
        item["ticket_id"] = ticket.ticket_id
        item["id"] = ticket.id
        item["status"] = status
        item["responsable"] = ticket.responsable
        item["manager"] = ticket.manager
        item["created_at"] = datetime.datetime.strptime(ticket.created_at, "%Y-%m-%d %H:%M:%S.%f").strftime("%m/%d/%Y, %H:%M:%S")
        result.append(item)

    return jsonify(result)


#### rafik ######################################################################### end
