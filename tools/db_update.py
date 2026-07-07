#!/usr/bin/env python3
""" database updater for est_proxy """
import os
import sys
import argparse
# pylint: disable=C0413
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from est_proxy.helper import logger_setup
from est_proxy.database import Database, DEFAULT_DB_FILE

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='db_update.py - est_proxy database updater')
    parser.add_argument('-d', '--dbfile', help='path to the est_proxy sqlite database', default=DEFAULT_DB_FILE)
    parser.add_argument('--debug', action='store_true', help='enable debug logging')
    args = parser.parse_args()

    logger = logger_setup(args.debug)

    db = Database(args.dbfile)
    logger.info('db_update.py: dbversion before update: %s', db.dbversion_get())
    db.db_update(logger)
    logger.info('db_update.py: dbversion after update: %s', db.dbversion_get())
