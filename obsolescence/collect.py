import requests

from database.connection import connect_to_db, close_connection


def collect_product_detail(url, product):
    response = requests.get(url)
    data = response.json()
    list_pro = []
    for element in data:

        dict_os = {}
        dict_os['product_cpe'] = product
        dict_os['version'] = element['cycle']
        if 'eol' in element:
            dict_os['eol'] = element['eol']
        else:
            dict_os['eol'] = ""
        if 'releaseDate' in element:
            dict_os['releaseDate'] = element['releaseDate']
        else:
            dict_os['releaseDate'] = ""
        if 'latest' in element:
            dict_os['latest'] = element['latest']
        else:
            dict_os['latest'] = ""

        if 'latestReleaseDate' in element:
            dict_os['latestReleaseDate'] = element['latestReleaseDate']
        else:
            dict_os['latestReleaseDate'] = ""
        if 'lts' in element:
            dict_os['lts'] = element['lts']
        else:
            dict_os['lts'] = ""

        if 'support' in element:
            dict_os['support'] = element['support']
        else:
            dict_os['support'] = ""

        list_pro.append(dict_os)
    print(list_pro)
    return list_pro


def collect_all_products():
    response = requests.get('https://endoflife.date/api/all.json')
    data = response.json()
    print('data', data)
    all_products = []
    for element in data:
        all_products.append(element)
    return all_products


def get_all_products_details():
    products = collect_all_products()
    print('products', products)
    connection = connect_to_db()
    cursor = connection.cursor(dictionary=True, buffered=True)
    for product in products:
        print('product', product)
        data = collect_product_detail(f'https://endoflife.date/api/{product}.json', product)

        insert_query = """INSERT IGNORE INTO obsolescence (product_cpe, version, eol, releaseDate, latest, latestReleaseDate, lts, support)
                                                  VALUES (%(product_cpe)s, %(version)s, %(eol)s, %(releaseDate)s, %(latest)s, %(latestReleaseDate)s, %(lts)s, %(support)s) """

        for i in data:
            cursor.execute(insert_query, i)
    connection.commit()
    cursor.close()
    close_connection(connection)
    return products
