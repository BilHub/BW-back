""" This module contains all the routes of the application. This routes link URLs withe the associated view functions (handlers) """
import csv
import datetime as dti
import os
import pathlib
import smtplib
import ssl
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# from config.conf import get_path
import pyotp
from flask import flash, jsonify
from flask import request
from flask_cors import cross_origin
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_login import current_user
from sqlalchemy import desc
from werkzeug.utils import secure_filename

from API.flask_app import app, db
from API.flask_app import models as m
from API.flask_app.models import requires_roles
from alert.sender import send_mime_mail_assign_ticket, send_mime_mail
from database.client import get_asset_id
from database.client import get_clients_info
from debug.debug import debug_log
from parsers.uni_parser import normalise_cpe_name


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

"""second method for authentication"""

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

        response = {"token": access_token, "user_id": user.id, "username": user.username,
                    "nom": user.nom,
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


""" Remove CPE from Asset by s_user"""

""" Ticket  management """
""" List tickets for user """

""" Show tickets information for Admin"""

""" Search tickets with filter """

""" Modify ticket """
""" Ticket  management """
""" List tickets for user """


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
    return jsonify({
        "msg": "I believe in the power of hard work and honesty. If you want to succeed, put in the effort and stay true to yourself and do not try to hack people"})


""" Add a new user """

""" Client administration """
""" Show user profile """

""" Modify user password """
""" CERT administration """
""" list all clients api"""

""" List all clients """


@app.route('/client-api/list')
def list_clients_api():
    """ list all clients """
    clients = get_clients_info()
    return jsonify(clients)


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

""" Remove client"""

""" Modify client """

""" List analysts """

""" Add a new analyst """
""" List pretickets for analyst """
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
""" List all users of a client """

""" Modify client user information """
""" delete user"""
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
""" Add a subscription plan """
""" Modify subscription plan """
""" Remove subscription plan"""
""" Add subscription to a client """
""" Change subscription"""
""" Extend subscription"""
""" Disable/Cancel subscription"""

""" Show subscription informations for client"""

""" 2FA authy functions """
""" Sign-up with authy """
""" Authy call back"""


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
    count_status_0 = 0
    count_status_1 =0
    closed_tickets = []
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
    outputList2_assets_x = []
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

    base_url = "https://demo.brightwatch.fr/brightwatch-demo/user-pages/reset-password/?token="
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

    last_tickets = m.Ticket_notification.query.filter_by(manager=current_user_id).order_by(desc(m.Ticket_notification.created_at))[:5]

    result = []

    for ticket in last_tickets:
        if ticket.status == -1:
            status = "Fermé"
        elif ticket.status == 0:
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
        item["created_at"] = datetime.datetime.strptime(ticket.created_at, "%Y-%m-%d %H:%M:%S.%f").strftime(
            "%m/%d/%Y, %H:%M:%S")
        result.append(item)

    return jsonify(result)

#### rafik ######################################################################### end
