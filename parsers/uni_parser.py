""" This module contains the functions that pars assets and products name of csv/Excel (convert them into a list of Assets/CPEs)  """


import csv
from datetime import datetime
from config.conf import get_path
from debug.debug import debug_log
import pandas as pd
import pathlib
#import tkinter as tk
#from tkinter import filedialog
from database.client import add_assets_to_client, get_client, link_asset_client
from database.asset import add_multiple_client_cpe


""" This function remove spaces and convert to lower case th product name or vendor"""
def normalise_cpe_name(name):
    cpe_name = name
    try:
        cpe_format = name.replace(' ','_')
        cpe_name = cpe_format.lower()
    except Exception as error:
        msg = 'Failed in  normalize_cpe_name: ' + str(error)
        debug_log('error', msg)
        # print("Failed to insert into cpe table {}".format(error))
    finally:
        return cpe_name


""" This function convert a csv file of assets to a liste of cpe """
def parse_csv(file_path):
    try:
        software_names = ['software', 'application']
        os_names = ['os', 'operating system']
        hardware_names = ['hardware']
        with open(file_path) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            asset_list = []
            for row in csv_reader:
                print(row) # debug
                if len(row) == 9:
                    if line_count == 0:
                        print(f'Column names are {", ".join(row)}')
                        line_count += 1
                        # print('type of csv line: ',type(row)) # debug
                    elif not row[0] or not row[1] or not row[2] or not row[3]:
                            print("mandatory columns are missing")
                    elif any(dict.get('asset_ref') == row[0] for dict in asset_list):  # the asset name (asset_ref) alredy exist in the list
                        for asset in asset_list:
                            """ find the asset in the asset name """
                            if asset['asset_ref'] == row[0]:
                                cpe23 = 'cpe:2.3:'
                                """ replace all blancs '' by '*' """
                                column_count = 0
                                for i in row:
                                    if i == '':
                                        row[column_count] = '*'
                                    column_count += 1
                                """ convert type to (a,h,o) """
                                type = row[1].lower()
                                if type in software_names:
                                    row[1] = 'a'
                                elif type in hardware_names:
                                    row[1] = 'h'
                                elif type in os_names:
                                    row[1] = 'o'
                                """ Remove space and convert to lower case"""
                                row[2] = normalise_cpe_name(row[2])
                                row[3] = normalise_cpe_name(row[3])

                                cpe = ':'.join(row[1:])
                                cpe_id = cpe23 + cpe
                                asset['cpes'].append(cpe_id)  # add the cpe_id to the list of cpes
                    else:
                        asset_ref = row[0]
                        cpe23 = 'cpe:2.3:'
                        """ replace all whitespaces '' by '*' """
                        column_count = 0
                        for i in row:
                            if i == '':
                                row[column_count] = '*'
                            column_count += 1
                        """ convert type to (a,h,o) """
                        type = row[1].lower()
                        if type in software_names:
                            row[1] = 'a'
                        elif type in hardware_names:
                            row[1] = 'h'
                        elif type in os_names:
                            row[1] = 'o'
                        """ Remove space and convert to lower case"""
                        row[2] = normalise_cpe_name(row[2])
                        row[3] = normalise_cpe_name(row[3])

                        cpe = ':'.join(row[1:5])
                        cpe_id = cpe23 + cpe
                        print('column 5', row[5])
                        print('column 6', row[6])
                        print('column 7', row[7])
                        asset_elem = {'asset_ref': asset_ref, 'cpes': [cpe_id], 'manager': row[5], 'responsable': row[6], 'service': row[7], 'importance': row[8]}
                        asset_list.append(asset_elem)

        """ Adding cpes to the DB (for those that does not exist already) """
        cpe_add_list = []
        for asset in asset_list:
            # print('\nasset : ', asset[3'asset_ref'])
            for cpe in asset['cpes']:
                """ Convert cpe id to cpe record """
                cpe_elem = cpe.split(':')
                # print('cpe elemnts: ',cpe_elem)
                type = cpe_elem[2]
                producer = cpe_elem[3].replace('()', ':')
                name = cpe_elem[4].replace('()', ':')
                version = cpe_elem[5].replace('()', ':')
                asset_element = [cpe, type, producer.strip(), name.strip(), version.strip()] # lstrip(): remove laeding and trailing whitespaces
                cpe_add_list.append(asset_element)
                # print('\t', asset_element)
        add_multiple_client_cpe(cpe_list=cpe_add_list)
        return asset_list
    except Exception as error:
        msg = 'Failed in parse_csv(): ' + str(error)
        debug_log('error', msg)
        print("Failed to parse csv file {}".format(error))


""" This function convert a csv file of assets to a liste of cpe """
def parse_xls(file_path,client): # client is the name of the company
   try:
       debug_log('debug', 'Start parse_xls()')
       """ convert csv to """
       columns_number = []
       for i in range(0, 12):
           columns_number.append(i)
       str_date = datetime.now().strftime("%Y_%m_%d")
       csv_file_name = 'invt_' + client + '_' + str_date
       csv_file_path = get_path('inventory') + csv_file_name + '.csv'
       data_xls = pd.read_excel(file_path, dtype=str,index_col=None, usecols=columns_number)
       data_xls.to_csv(csv_file_path, encoding='utf-8', index=False)
       """ Parse the csv file """
       asset_list = parse_csv(csv_file_path)
       """ Printing the result """
       # for asset in asset_list:
       #     print('\nasset : ', asset['asset_ref'])
       #     for cpe in asset['cpes']:
       #         print('\t', cpe)
       # return asset_list
       # print('sheet.max_row: ',sheet.max_row) # number of lines of the sheet
       # print('sheet.max_row: ',sheet.max_column) # number of lines of the sheet
       # columns_name = ['A','B','C','D','E','F','G','H','I','J','K','L']
       # for row in range(2, sheet.max_row):
       #     actif = sheet['A' + str(row)].value
       #     type = sheet['B' + str(row)].value
       #     vendor = sheet['C' + str(row)].value
       #     product = sheet['D' + str(row)].value
       #     version = sheet['E' + str(row)].value
       #     update = sheet['F' + str(row)].value
       #     edition = sheet['G' + str(row)].value
       #     langge = sheet['H' + str(row)].value
       #     sw_edition = sheet['I' + str(row)].value
       #     targt_sw = sheet['J' + str(row)].value
       #     target_hw = sheet['K' + str(row)].value
       #     other = sheet['L' + str(row)].value
       #     print(actif+':')

   except Exception as error:
       msg = 'Failed in parse_xls() ' + str(error)
       debug_log('error', msg)
       print("Failed to parse xls file {}".format(error))
   finally:
       debug_log('debug', 'Start parse_xls()')
       if asset_list:
           return asset_list
       else:
           return []

""" This function redirect the file to the appropriate parser """
def parse_all(file_path,client): # client is the name of the company
    debug_log('debug', 'Start parse_all')
    assets_list = []
    try:
       excel_extentions = ['.xls', '.xlsx', '.xlsm', '.xlsb', '.odf', '.ods', '.odt']
       csv_extention = '.csv'
       file_extension = pathlib.Path(file_path).suffix
       print("File Extension: ", file_extension)
       if file_extension == csv_extention:
           assets_list = parse_csv(file_path)
       elif file_extension in excel_extentions:
           assets_list = parse_xls(file_path,client)


       return assets_list
    except Exception as error:
       msg = 'Failed in parse_all() ' + str(error)
       debug_log('error', msg)
       print("Failed to parse file {}".format(error))
    finally:
        debug_log('debug', 'End parse_all')
        return assets_list
