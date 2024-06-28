""" This module contains functions that build an html mail containing vulnerabilities information """


from tldextract import extract
from debug.debug import debug_log



""" extract readable asset name """
def get_asset_name(id_cpe):
    # debug_log('debug','Start get_asset_name()')
    cpe_elem = id_cpe.replace(':*', '')
    # print('cpe_elem: ',cpe_elem)
    cpe_list = cpe_elem.split(':')
    # print('cpe_list: ', cpe_list)
    cpe_str = ' '.join(cpe_list[3:])
    # print('cpe_str: ', cpe_str)
    cpe_name = cpe_str.replace('_',' ')
    # print(cpe_name)
    # debug_log('debug','End get_asset_name()')
    return cpe_name


""" Extract domain name"""
def get_domain_name(url):
    # debug_log('debug','Start get_domain_name()')
    ext = extract(url)
    if ext != "":
        # debug_log('debug','End get_domain_name()')
        return ext.domain
    else:
        debug_log('debug','End get_domain_name()')
        return url


""" Build a n html personalised Alert """
def make_alert(params): # params: {'assets': ref_list, 'list_assets': i['asset_cve_list'], 'links': i['links']}
    debug_log('debug','Start make_alert()')
    list_asset = ""
    links = ""
    ref_list = ""
    cve_pattern = 'CVE-\d{4}-\d+'

    """ Get vulnerable_cpe/CVEs list"""
    table_body = ""
    for i in params['list_assets']: # list_assets: {'cpe': cpe, 'ref_list':ref_list, 'cve_list': cve_list}
        # build cve, score and links column
        cves = ""
        links_list = []
        cvssv2 = ''
        cvssv3 = ''
        for cve in i['cve_list']:
            link = f"""https://nvd.nist.gov/vuln/detail/{cve['id_cve']}"""
            cves = cves + f"""<a href="{link}">{cve['id_cve']}</a>""" + '<br>'
            # cves = cves + cve['id_cve'] + '<br>'
            # add the links of the CVEs to list
            link_tab = cve['links'].split(', ')
            # print('link_tab: ',link_tab) # debugging
            # Getting the CVSSv2 score
            if cve['cvss2']:
                c2 = str(cve['cvss2'])
            else:
                c2 = '-'
            cvssv2 = cvssv2 + c2 + '<br>'

            # Getting the CVSSv3 score
            if cve['cvss3']:
                c3 = str(cve['cvss3'])
            else:
                c3 = '-'
            cvssv3 = cvssv3 + c3 + '<br>'

            for l in link_tab:
                if l not in links_list and len(links_list)<10: # show 10 sources max to avoid too long columns
                    links_list.append(l)

        # get the links
        cve_links = ""
        # print('links_list: ',links_list) # debugging
        for li in links_list:
            # cve_links = cve_links + li + '<br>'
            domain = get_domain_name(li)
            cve_links = cve_links + f"""<a href="{li}">{domain.upper()}</a>""" + '<br>'
        # build asset_ref row
        asset_refs ="<ul> "
        for ref in i['ref_list']:
            ref_line = f"""<li>{ref}</li> """
            asset_refs = asset_refs + ref_line
        asset_refs = asset_refs + '</ul>'

        asset = get_asset_name(i['cpe']) # concert cpe_id to asset name
        asset_name = asset.title()
        table_row = f"""
        <tr>
        <td style="text-align:center" scope="row" align="left">{asset_name}</td>
        <td style="text-align:left" align="left">{asset_refs}</td>
        <td style="text-align:center" align="center">{cves}</td>
        <td style="text-align:center" align="center">{cvssv2}</td>
        <td style="text-align:center" align="center">{cvssv3}</td>
        <td style="text-align:center;width:5%;" align="center">{cve_links}</td>   
        </tr> 
        """
        table_body = table_body + table_row + '\n'
        cve_list = "\tCVEs: "
        for c in i['cve_list']:
            cve_list = cve_list + c['id_cve'] + "; "
        asset = get_asset_name(i['cpe'])
        list_asset = list_asset + '<li>' + asset.title() +'<br>'+ cve_list[:-2] + '</li>'

    """ Get links list"""
    for l in params['links']:
        # match = re.search(cve_pattern,l)
        # cve_id = match.group()
        # link = f"""<a href="{l}">{}</a>"""
        # links = links + link + '; '
        links = links + l + '; '
    """ Get client asset_ref list"""
    for r in params['assets']:
        ref_list = ref_list + '<li>' + r + "</li>"
    ref_list = ref_list[:-2]

    html = f"""\
    <html>
      <body>
    <p>
    Bonjour, 
     <br>
      <br>
    Vous êtes inscrit(e) au service Brightwatch.
    <br>
    Une ou plusieurs vulnérabilités sont apparues affectant vos actifs; vous êtes invité(e) à vous connecter à votre Tableau de bord pour en prendre connaissance.
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

    # .format(nb_assets=params['nb_assets'],list_assets=params['list_assets'],link=params['link'])
    debug_log('debug','End make_alert()')
    """ Return the body of the alert """
    return html


def make_alert_assign_ticket():  # params: {'assets': ref_list, 'list_assets': i['asset_cve_list'], 'links': i['links']}


    html = """
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

    # .format(nb_assets=params['nb_assets'],list_assets=params['list_assets'],link=params['link'])
    debug_log('debug', 'End make_alert()')
    """ Return the body of the alert """
    return html





