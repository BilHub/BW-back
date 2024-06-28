""" This module contain the logging function """



import logging
from config.conf import get_path


# add a debug message into the debug file
def debug_log(msg_type,msg):
    path = get_path('debug')
    # info that can be added in the format: %(threadName)s %(Name)s
    logging.basicConfig(filename=path, level=logging.DEBUG,
                        format='%(asctime)s %(name)s  %(levelname)s  %(message)s')
    # print('dbeug_log executed!')
    if msg_type == 'debug':
        # print('debug message!')
        logging.debug(msg)
    elif msg_type == 'error':
        # print('error message!')
        logging.error(msg)
    elif msg_type == 'info':
        logging.info(msg)

def debug_new_line():
    path = get_path('debug')
    with open(path, 'a') as df:
        df.write('\n')


""" Testing """
# debug_new_line()
# debug_log('error','error message added')
# debug_log('debug','debug message added')
# error_log('new log error message')
