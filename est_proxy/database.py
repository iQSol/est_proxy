#!/usr/bin/python

import sqlite3

from typing import Any
from datetime import datetime
from os.path import exists

import bcrypt

from est_proxy.version import __dbversion__

DEFAULT_DB_FILE = '/usr/local/est_proxy/data/est_proxy.db'

class Database():
    db_file: str = None
    db_con: sqlite3.Connection = None
    db_cur: sqlite3.Cursor = None

    def __init__(self, db_file: str) -> None:
        self.db_file = db_file

        if not exists(self.db_file):
            self.__create()

    def db_update(self, logger: Any = None) -> None:
        """ idempotent schema migration entrypoint """

        self.__connect()

        # create the housekeeping table (and its modified_at trigger) if missing
        self.db_cur.execute('''
            CREATE TABLE IF NOT EXISTS housekeeping
            (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            value TEXT,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            ''')

        self.db_cur.execute('''
            CREATE TRIGGER IF NOT EXISTS housekeeping_update_modified_at
            AFTER UPDATE ON housekeeping
            FOR EACH ROW
            WHEN NEW.modified_at <= OLD.modified_at
            BEGIN
                UPDATE housekeeping SET modified_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END
            ''')

        self.__update_certificates_fk(logger)
        self.__update_users_auth_backend(logger)

        self.__dbversion_set()

        self.__commit_and_close()

    def dbversion_get(self) -> Any:
        """ get the current schema version from the housekeeping table """

        self.__connect()
        self.db_cur.execute('''SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'housekeeping' ''')
        table_exists: bool = self.db_cur.fetchone()[0] == 1

        result: Any = None
        if table_exists:
            self.db_cur.execute('''SELECT value FROM housekeeping WHERE name = 'dbversion' ''')
            item: Any = self.db_cur.fetchone()
            if item:
                result = item['value']

        self.__commit_and_close()

        return result

    @staticmethod
    def _password_value(password: str) -> str:
        """ bcrypt hash; '' for radius users (never matches any hash) """
        if not password:
            return ''
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def insert_or_update_user(self, username: str, password: str, template: str, common_name_regex: str, ip_regex: str = "", dns_regex: str = "", auth_backend: str = "local") -> bool:
        """ inserts or updates a user"""

        self.__connect()
        self.db_cur.execute('''SELECT id FROM users WHERE username = ?''', (username,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''
                UPDATE users SET username = ?, password = ?, template = ?, common_name_regex = ?, ip_regex = ?, dns_regex = ?, auth_backend = ? WHERE id = ?
                ''', (username, self._password_value(password), template, common_name_regex, ip_regex, dns_regex, auth_backend, item['id'])
            )
        else:
            self.db_cur.execute('''
                INSERT INTO users(username,password,template,common_name_regex,ip_regex,dns_regex,auth_backend)
                VALUES (?, ?, ?, ?, ?, ?, ?)''', (username, self._password_value(password), template, common_name_regex, ip_regex, dns_regex, auth_backend)
            )

        self.__commit_and_close()

        return True

    def update_user_password(self, username: str, password: str) -> bool:
        """ set a new (bcrypt hashed) password for an existing user """

        result = False

        self.__connect()
        self.db_cur.execute('''SELECT id FROM users WHERE username = ?''', (username,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''UPDATE users SET password = ? WHERE id = ?''', (self._password_value(password), item['id']))
            result = True

        self.__commit_and_close()

        return result

    def delete_user(self, username: str):
        """ deletes a authentication user """

        result = False

        self.__connect()
        self.db_cur.execute('''SELECT id FROM users WHERE username = ?''', (username,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''DELETE FROM users WHERE id = ?''', (item['id'],))
            result = True

        self.__commit_and_close()

        return result

    def get_user(self, username: str) -> Any:
        """ get one user by username"""

        self.__connect()
        self.db_cur.execute('''SELECT * FROM users WHERE username = ?''', (username,))

        item: Any = self.db_cur.fetchone()
        self.__commit_and_close()

        return item

    def get_user_by_id(self, id: int) -> Any:
        "get one user by id"

        self.__connect()
        self.db_cur.execute('''SELECT * FROM users WHERE id = ?''', (id,))

        item: Any = self.db_cur.fetchone()
        self.__commit_and_close()

        return item


    def insert_or_update_certificate(self, common_name: str, valid_from: datetime, valid_to: datetime, user_id: int)  -> bool:
        """ inserts a certificate"""

        self.__connect()
        self.db_cur.execute('''SELECT id FROM certificates WHERE common_name = ?''', (common_name,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''
                UPDATE certificates SET common_name = ?, valid_from = ?, valid_to = ?, user_id = ? WHERE id = ?
                ''', (common_name, valid_from, valid_to, user_id, item['id'])
            )
        else:
            # Insert
            self.db_cur.execute('''
                INSERT INTO certificates(common_name,valid_from,valid_to,user_id)
                VALUES (?, ?, ?, ?)''', (common_name, valid_from, valid_to, user_id)
            )

        self.__commit_and_close()

        return True

    def delete_certificate(self, common_name: str):
        """ delete certificate """

        result = False

        self.__connect()
        self.db_cur.execute('''SELECT id FROM certificates WHERE common_name = ?''', (common_name,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''DELETE FROM certificates WHERE id = ?''', (item['id'],))
            result = True

        self.__commit_and_close()

        return result

    def get_certificate(self, common_name: str):
        """ get one certificate """

        self.__connect()
        self.db_cur.execute('''SELECT * FROM certificates WHERE common_name = ?''', (common_name,))

        item: Any = self.db_cur.fetchone()
        self.__commit_and_close()

        return item

    def __connect(self) -> None:
        """ Connects to the sqlite3 database. """

        self.db_con = sqlite3.connect(self.db_file)
        self.db_con.row_factory = sqlite3.Row
        self.db_cur = self.db_con.cursor()

    def __create(self) -> None:
        """ Creates the sqlite3 database for the est proxy. """

        self.__connect()

        self.db_cur.execute('''
            CREATE TABLE IF NOT EXISTS users
            (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            template TEXT,
            common_name_regex TEXT,
            ip_regex TEXT,
            dns_regex TEXT,
            auth_backend TEXT NOT NULL DEFAULT 'local'
            )
            ''')

        self.db_cur.execute('''
            CREATE TABLE IF NOT EXISTS certificates
            (
            id INTEGER PRIMARY KEY,
            common_name TEXT,
            valid_from DATETIME,
            valid_to DATETIME,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
            )''')

        self.db_cur.execute('''
            CREATE TABLE IF NOT EXISTS housekeeping
            (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            value TEXT,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            ''')

        self.db_cur.execute('''
            CREATE TRIGGER IF NOT EXISTS housekeeping_update_modified_at
            AFTER UPDATE ON housekeeping
            FOR EACH ROW
            WHEN NEW.modified_at <= OLD.modified_at
            BEGIN
                UPDATE housekeeping SET modified_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END
            ''')

        self.db_cur.execute('''INSERT OR IGNORE INTO housekeeping (name, value) VALUES ('dbversion', ?)''', (str(__dbversion__),))

        self.__commit_and_close()

    def __update_certificates_fk(self, logger: Any = None) -> None:
        """ rebuild the certificates table if its FK still points at the (non-existent) users.user_id column """

        self.db_cur.execute('''PRAGMA foreign_key_list(certificates)''')
        fk_list: Any = self.db_cur.fetchall()
        legacy_fk: bool = any(row['table'] == 'users' and row['to'] == 'user_id' for row in fk_list)

        if legacy_fk:
            if logger:
                logger.info('Database.db_update(): rebuilding certificates table - fixing user_id foreign key')
            self.db_cur.execute('''ALTER TABLE certificates RENAME TO tmp_certificates''')
            self.db_cur.execute('''
                CREATE TABLE certificates
                (
                id INTEGER PRIMARY KEY,
                common_name TEXT,
                valid_from DATETIME,
                valid_to DATETIME,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
            self.db_cur.execute('''
                INSERT INTO certificates(id, common_name, valid_from, valid_to, user_id)
                SELECT id, common_name, valid_from, valid_to, user_id FROM tmp_certificates
                ''')
            self.db_cur.execute('''DROP TABLE tmp_certificates''')

    def __update_users_auth_backend(self, logger: Any = None) -> None:
        """ add the auth_backend column to the users table if missing """

        self.db_cur.execute('''PRAGMA table_info(users)''')
        column_list: Any = [column['name'] for column in self.db_cur.fetchall()]

        if 'auth_backend' not in column_list:
            if logger:
                logger.info('Database.db_update(): alter users table - add auth_backend column')
            self.db_cur.execute('''ALTER TABLE users ADD COLUMN auth_backend TEXT NOT NULL DEFAULT 'local' ''')

    def __dbversion_set(self) -> None:
        """ store the current schema version in the housekeeping table """

        self.db_cur.execute('''INSERT OR IGNORE INTO housekeeping (name, value) VALUES ('dbversion', ?)''', (str(__dbversion__),))
        self.db_cur.execute('''UPDATE housekeeping SET value = ? WHERE name = 'dbversion' ''', (str(__dbversion__),))

    def __commit_and_close(self) -> None:
        """ Commits and closes the connection."""

        self.db_con.commit()
        self.db_con.close()
