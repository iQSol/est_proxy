#!/usr/bin/python

import sqlite3

from typing import Any
from datetime import datetime
from os.path import exists
from hashlib import sha512

class Database():
    db_file: str = None
    db_con: sqlite3.Connection = None
    db_cur: sqlite3.Cursor = None

    def __init__(self, db_file: str) -> None:
        self.db_file = db_file

        if not exists(self.db_file):
            self.__create()

    def insert_or_update_user(self, username: str, password: str, template: str, common_name_regex: str, ip_regex: str = "", dns_regex: str = "") -> bool:
        """ inserts or updates a user"""

        self.__connect()
        self.db_cur.execute('''SELECT id FROM users WHERE username = ?''', (username,))

        item: Any = self.db_cur.fetchone()

        if item:
            self.db_cur.execute('''
                UPDATE users SET username = ?, password = ?, template = ?, common_name_regex = ?, ip_regex = ?, dns_regex = ? WHERE id = ?
                ''', (username, sha512(password.encode()).hexdigest(), template, common_name_regex, ip_regex, dns_regex, item['id'])
            )
        else:
            self.db_cur.execute('''
                INSERT INTO users(username,password,template,common_name_regex,ip_regex,dns_regex)
                VALUES (?, ?, ?, ?, ?, ?)''', (username, sha512(password.encode()).hexdigest(), template, common_name_regex, ip_regex, dns_regex)
            )

        self.__commit_and_close()

        return True

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
            dns_regex TEXT
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
            FOREIGN KEY (user_id) REFERENCES users(user_id)
            )''')

        self.__commit_and_close()

    def __commit_and_close(self) -> None:
        """ Commits and closes the connection."""

        self.db_con.commit()
        self.db_con.close()
