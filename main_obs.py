from collector.vuln_collect import collect_vulnerabilities
from collector.vuln_store import store_vulnerabilities
from debug.debug import debug_new_line, debug_log
from database.cve import purge_cve_temp
from obsolescence.collect import get_all_products_details, get_all_products_details
from obsolescence.matching import get_existing_data_db
from database.connection import connect_to_db, close_connection
import schedule
import time


""" collect CVE in schedule task """
def scheduled_collect(): #
    try:
        debug_new_line()
        debug_log('debug', 'Start scheduled_collect()')
        print('Lunching the collect ...')
       # products = get_all_products_details()
       # get_existing_data_db()
        cves = collect_vulnerabilities()
        # store_vulnerabilities(cves) # store collected cves in the DB

    except Exception as error:
        msg = 'Failed in scheduled_collect(): ' + str(error)
        debug_log('error', msg)
    finally:
        debug_log('debug', 'End scheduled_collect()')


""" delete collected CVEs for the last 24 hours """
def clear_CVEs(): #
    try:
        debug_log('debug', 'Start clear_CVEs()')
        purge_cve_temp()
    except Exception as error:
        msg = 'Failed in clear_CVEs(): ' + str(error)
        debug_log('error', msg)
    finally:
        debug_log('debug', 'End clear_CVEs()')


if __name__ == '__main__':
    print('main')
    """ Clear cve_temp table """
    # purge_cve_temp()

    debug_new_line()
    # cves = collect_vulnerabilities()
    get_existing_data_db()
    # schedule.every(4).hours.do(scheduled_collect) # test PGV v0.2
   # schedule.every(1).minutes.do(scheduled_collect) # for testing
   # schedule.every(24).hours.do(purge_cve_temp) # for testing

    """ Starting the test """
    while True:
        schedule.run_pending()  # run all functions tha are scheduled to run
        # pause_time = 13500  # suspend the execution of the thread for 2 hours
        pause_time = 120  # suspend the execution of the thread for 2 minutes
        # time.sleep(pause_time)

    # cves = collect_vulnerabilities()
    # """ Storing collected vulnerabilities ini the database """
    # store_vulnerabilities(cves)
