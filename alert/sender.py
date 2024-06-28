""" This module contains functions that sends alerts (mails) to a list of client users"""



import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from datetime import datetime
from database.connection import connect_to_db, close_connection
from alert.construct import make_alert
import numpy as np
from database.alert import add_aut_alert, update_aut_alert, add_multi_usage_aut_alert
from debug.debug import debug_log


""" Sending an htm mail with plaintext alternative usig MIME mail"""
def send_mime_mail(receiver, message):
    debug_log('debug','Start send_mime_mail()')
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
             server.sendmail(sender_email,receiver,message.as_string())
             print('Mime mail sent successfully to: ',receiver)

        # Using smtp without ssl (NOT WORKING)
        # with smtplib.SMTP("smtp.gmail.com",port=25) as server: # Testing smtp without ssl
            # server.connect("smtp.gmail.com")
            # server.helo()
            # server.sendmail(sender_email, receiver, message.as_string())

        msg = f"""mail sent successfully to {receiver}"""
        debug_log('info', msg)



    except Exception as e:
        msg = 'Failed in send_mime_mail(): ' + str(e)
        debug_log('error',msg)
        print('Error send_mime_mail: ',str(e))
        published_on = None
    finally:
        debug_log('debug','End send_mime_mail()')
        return published_on

def send_mime_mail_assign_ticket(receiver, message):
    debug_log('debug','Start send_mime_mail()')
    print('sending email')
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
             server.sendmail(sender_email,receiver,message.as_string())
             print('Mime mail sent successfully to: ',receiver)

        # Using smtp without ssl (NOT WORKING)
        # with smtplib.SMTP("smtp.gmail.com",port=25) as server: # Testing smtp without ssl
            # server.connect("smtp.gmail.com")
            # server.helo()
            # server.sendmail(sender_email, receiver, message.as_string())

        msg = f"""mail sent successfully to {receiver}"""
        debug_log('info', msg)



    except Exception as e:
        msg = 'Failed in send_mime_mail(): ' + str(e)
        debug_log('error',msg)
        print('Error send_mime_mail: ',str(e))
        published_on = None
    finally:
        debug_log('debug','End send_mime_mail()')
        return published_on
def send_alerts(connection,client_assets_list):
        debug_log('debug','Start send_alerts()')
        start_time = time.time()
        print('\nSending alerts ...')
    # try:
    # if 1==1:
        sender_email = 'pgv.brightway@gmail.com'
        # print('Number of clients who will be alerted: ',len(client_assets_list))
        for i in client_assets_list:  # i :
            ref_list = [] # old configuration
            for r in i['asset_cve_list']: # old configuration
                # print(type(r['ref_list']))
                # print('ref_list: ', ref_list)
                # print('r[ref_list]: ',r['ref_list'])
                ref_list.extend(r['ref_list']) # old configuration
            ref_list = np.unique(ref_list + r['ref_list'])
            params = {'assets': ref_list, 'list_assets': i['asset_cve_list'], 'links': i['links']} # old configuration
            # print('links: ',i['links'])
            # print(f"Number of assets vulnerable of the client {sender_email} is: ",len(i['vuln_assets'])) # old configuration
            """ get the client mail """
            # select_Query = """ select email from user where groupe = %s and role = 'ad_user' """ # sending mail only to admin user

            # cursor = connection.cursor(dictionary=True)
            # query_arg = (i['client'],)
            # cursor.execute(select_Query, query_arg)
            # record = cursor.fetchone() # Send the alert only to one person from the company

            # receiver = record['email']
            select_Query = """ select email from user where id = %s  """  # sending mail only to the responsable of the asset
            query_arg = (i['responsable'],)
            connection = connect_to_db()
            cursor = connection.cursor(dictionary=True)
            cursor.execute(select_Query, query_arg)
            record = cursor.fetchone()  # Send the alert only to one person from the company
            receiver_to = record['email']



            """ get the asset responsable email"""




            # print('Receiver of the mail: ',receiver)
            # body = make_alert(i['asset_cve_list'])
            body = make_alert(params)
            # print('Body of the mail: ',body)
            text = """\
           
Besoin de notre aide ? vous pouvez nous contacter sur contact@brightway.fr.
              
             """ # for test

            message = MIMEMultipart("alternative")
            subject = "[Brightwatch] Nouvelle alerte"
            message["Subject"] = subject
            message["From"] = sender_email
            message["To"] = receiver_to
            # message["CC"] = receiver
            # Turn these into plain/html MIMEText objects
            part1 = MIMEText(text, "plain")
            part2 = MIMEText(body, "html")
            # Add HTML/plain-text parts to MIMEMultipart message
            # The email client will try to render the last part first
            message.attach(part1)
            message.attach(part2)

            now = datetime.now()
            created_at = now.strftime("%Y-%m-%d %H:%M:%S")
            record = {'title':subject,'message':body,'links':None,'created_at':created_at,'status':0,'solutions':None,'published_on':None,'score': None, 'responsable':i['responsable']}
            add_aut_alert(record,connection)
            debug_log('info','alert added to the database')

            published_on = send_mime_mail(receiver_to, message)
            if published_on:
                """ Update the alert sending datetime and the status of the alert in aut_alert table"""
                select_Query = """ select id from aut_alert where created_at = %s """
                query_arg = (created_at,)
                cursor.execute(select_Query, query_arg)
                record = cursor.fetchone()
                # print('selected id record: ',record)
                alert_id = record['id']
                status = 1  # 1: alert sent
                update_aut_alert(alert_id, published_on, status, cursor)
                connection.commit()

                """ Link the alert with the client vulnerable assets and cves (join: add records to usage_aut_alert table)"""
                add_list = []
                for a in i['asset_cve_list']:  # asset_cve_list element: {'asset':'cpe_id', 'cve_list':['cve_id','cve_id',...]}
                    # print('cpe: ',a, '\tnumber of CVE: ',len(a['cve_list']))
                    for ref in a['ref_list']:
                        select_Query = """ select au.id from asset_usage au, asset a where a.asset_ref = %s AND au.cpe = %s AND a.groupe = %s AND au.asset_id = a.id """
                        query_arg = (ref, a['cpe'], i['client'])
                        cursor.execute(select_Query, query_arg)
                        record = cursor.fetchone()
                        # print('selected id record: ',record)
                        usage_id = record['id']
                        if usage_id:  # if the select record is not empty
                            for c in a['cve_list']:
                                element = [alert_id, usage_id, c['id_cve']]
                                add_list.append(element)
                # print('\nUsage_aut_alert entries: ',len(add_list))
                # for u in add_list:
                #     print(u)
                add_multi_usage_aut_alert(add_list, cursor)
                connection.commit()

    # except Exception as e:
    #     print('Failed in send_alerts(): ', str(e))
    #     msg = 'Failed in send_alerts(): ' + str(e)
    #     debug_log('error',msg)

    # finally:
        """ calculate the execution time of the function """
        end_time = time.time()
        exec_time = end_time - start_time
        print('send_alerts execution time: ', time.strftime("%H:%M:%S", time.gmtime(exec_time)), '\n')
        debug_log('debug','End send_alerts()')


""" Sending mail with attcahement """
# def send_mail_with_pdf(receiver,message,filename): # not used now
#     try:
#         port = 465  # For SSL
#         # password = input('Mot de passe : ')
#         password = 'test.1120!BR'
#         sender_email = 'pgv.brightway@gmail.com'
#
#         # Open PDF file in binary mode
#         with open(filename, "rb") as attachment:
#             # Add file as application/octet-stream
#             # Email client can usually download this automatically as attachment
#             part = MIMEBase("application", "octet-stream")
#             part.set_payload(attachment.read())
#
#         # Encode file in ASCII characters to send by email
#         encoders.encode_base64(part)
#
#         # Add header as key/value pair to attachment part
#         part.add_header(
#             "Content-Disposition",
#             f"attachment; filename= {filename}", # this is necessary to name the attachement in the mail
#         )
#
#         # Add attachment to message and convert message to string
#         message.attach(part)
#
#         # Log in to server using secure context and send email
#         context = ssl.create_default_context()
#         with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
#             server.login(sender_email, password)
#             server.sendmail(sender_email, receiver, message.as_string())
#             print('Mail with PDF sent successfully to: ', receiver)
#
#     except Exception as e:
#         print('Can\'t send mail with pdf: ', e)

def send_reset_password_mail(input_email, generated_token):

    # print('Body of the mail: ',body)
    text = """\

    Besoin de notre aide ? vous pouvez nous contacter sur contact@brightway.fr.

                 """  # for test
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
    part = MIMEText(html,  _charset="utf-8", _subtype="html")
    message.attach(part)
    published_on = send_mime_mail(input_email, message)
    return published_on