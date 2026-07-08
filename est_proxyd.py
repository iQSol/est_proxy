#!/usr/bin/env python3
""" start script for est_proxy """
import os
import sys
import argparse
# pylint: disable=C0413
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)))
from est_proxy.helper import config_load, logger_setup
from est_proxy.est_handler import ESTSrvHandler
from est_proxy.secureserver import SecureServer
from est_proxy.version import __version__

def _arg_parse():
    """ simple argparser """
    parser = argparse.ArgumentParser(description='est_proxyd.py - est_proxy start script')
    parser.add_argument('-c', '--config', help='configuration file ', default='/etc/est_proxy.cfg')
    args = parser.parse_args()
    config_file = args.config

    if not os.path.isfile(config_file):
        print('Could not load config file: {0}. Aborting...'.format(config_file))

    return config_file

def _config_load(debug=None, cfg_file=None):
    """ load config from file """
    config_dic = config_load(debug, cfg_file=cfg_file)
    try:
        debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)
    except BaseException:
        debug = False

    svc_dic = {}
    if 'Daemon' in config_dic:
        svc_dic['Daemon'] = {}
        svc_dic['Daemon']['address'] = config_dic.get('Daemon', 'address', fallback=None)
        try:
            svc_dic['Daemon']['port'] = int(config_dic.get('Daemon', 'port', fallback='1443'))
        except ValueError:
            print('defaulting port to 1443')
            svc_dic['Daemon']['port'] = 1443

    return(debug, svc_dic)

def srv_run(logger, server_class=SecureServer, handler_class=ESTSrvHandler, address='127.0.0.1', port=8080, cfg_file='/etc/est_proxy.cfg'):
    """ function to start server """
    logger.debug('srv_run({0})'.format(port))

    server_address = (address, port)
    httpd = server_class(server_address, handler_class, cfg_file=cfg_file)
    logger.info('starting est_proxy {2} on {0}:{1}'.format(address, port, __version__))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info('srv_run(): keyboard interrupt')
    httpd.server_close()
    logger.info('stopping est_proxy on {0}:{1}'.format(address, port))

if __name__ == '__main__':

    # parse --config option
    CFG_FILE = _arg_parse()

    # load config file and initialize logging
    (DEBUG, SVC_DIC) = _config_load(cfg_file=CFG_FILE)
    LOGGER = logger_setup(DEBUG, cfg_file=CFG_FILE)

    if 'Daemon' in SVC_DIC:
        # start est service supporting  Daemon
        srv_run(logger=LOGGER, address=SVC_DIC['Daemon']['address'], port=SVC_DIC['Daemon']['port'], cfg_file=CFG_FILE)
    else:
        LOGGER.error('No est-services enabled in {0}'.format(CFG_FILE))
