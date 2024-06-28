import logging


# add an error message into the logging file
def error_log(error):
    logging.basicConfig(filename='debug/pgv_error.log', level=logging.ERROR, format='%(asctime)s \t %(levelname)s \t %(message)s')
    logging.error(error)



""" Testing """
# error_log('new log error message')

# debug_new_line()
# debug_log('debug message added')
# debug_log('debug message added')