#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for database """
# pylint: disable=C0415, E0401
import unittest
import sqlite3
import sys
import os
import tempfile
from unittest.mock import Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class DatabaseTestCases(unittest.TestCase):
    """ test class for database """

    def setUp(self):
        """ setup """
        from est_proxy.database import Database
        from est_proxy.version import __dbversion__
        self.Database = Database
        self.dbversion = __dbversion__
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_file = os.path.join(self.tmp_dir.name, 'est_proxy.db')

    def tearDown(self):
        """ teardown """
        self.tmp_dir.cleanup()

    def _users_columns(self, db_file):
        """ helper: returns the column names of the users table """
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        cur.execute('''PRAGMA table_info(users)''')
        columns = [row[1] for row in cur.fetchall()]
        con.close()
        return columns

    def _certificates_fk(self, db_file):
        """ helper: returns the (table, to-column) tuple of the certificates FK, or None """
        con = sqlite3.connect(db_file)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute('''PRAGMA foreign_key_list(certificates)''')
        row = cur.fetchone()
        con.close()
        if not row:
            return None
        return (row['table'], row['to'])

    def test_fresh_install_creates_housekeeping_table(self):
        """ a brand new database gets a housekeeping table with the current dbversion """
        db = self.Database(self.db_file)
        self.assertEqual(db.dbversion_get(), str(self.dbversion))

    def test_fresh_install_has_correct_certificates_fk(self):
        """ a brand new database's certificates table FK references users(id) """
        self.Database(self.db_file)
        self.assertEqual(self._certificates_fk(self.db_file), ('users', 'id'))

    def test_legacy_db_gets_housekeeping_table_on_update(self):
        """ a pre-migration database gets a housekeeping table after db_update() """
        self._create_legacy_db()

        db = self.Database(self.db_file)
        self.assertIsNone(db.dbversion_get())

        db.db_update()
        self.assertEqual(db.dbversion_get(), str(self.dbversion))

    def test_legacy_db_certificates_fk_gets_fixed_on_update(self):
        """ a pre-migration database's broken certificates FK is corrected by db_update() """
        self._create_legacy_db()

        db = self.Database(self.db_file)
        self.assertEqual(self._certificates_fk(self.db_file), ('users', 'user_id'))

        db.db_update()
        self.assertEqual(self._certificates_fk(self.db_file), ('users', 'id'))

    def test_legacy_db_certificate_rows_survive_update(self):
        """ existing certificate rows survive the FK-fixing table rebuild """
        self._create_legacy_db()

        con = sqlite3.connect(self.db_file)
        cur = con.cursor()
        cur.execute('''INSERT INTO users(username, password) VALUES ('foo', 'bar')''')
        cur.execute('''INSERT INTO certificates(common_name, valid_from, valid_to, user_id) VALUES ('foo.example.com', '2020-01-01', '2030-01-01', 1)''')
        con.commit()
        con.close()

        db = self.Database(self.db_file)
        db.db_update()

        certificate = db.get_certificate('foo.example.com')
        self.assertEqual(certificate['common_name'], 'foo.example.com')
        self.assertEqual(certificate['user_id'], 1)

    def test_fresh_install_has_auth_backend_column(self):
        """ a brand new database's users table already has the auth_backend column """
        self.Database(self.db_file)
        self.assertIn('auth_backend', self._users_columns(self.db_file))

    def test_legacy_db_gets_auth_backend_column_on_update(self):
        """ a pre-migration database gets the auth_backend column after db_update() """
        self._create_legacy_db()
        self.assertNotIn('auth_backend', self._users_columns(self.db_file))

        db = self.Database(self.db_file)
        db.db_update()

        self.assertIn('auth_backend', self._users_columns(self.db_file))

    def _info_messages(self, logger):
        """ helper: list of the message strings passed to logger.info """
        return [call.args[0] for call in logger.info.call_args_list]

    def test_legacy_db_update_logs_auth_backend_column_add(self):
        """ adding the auth_backend column on a legacy db logs an info message """
        self._create_legacy_db()
        logger = Mock()
        self.Database(self.db_file).db_update(logger)
        self.assertIn('Database.db_update(): alter users table - add auth_backend column',
                      self._info_messages(logger))

    def test_legacy_db_update_logs_certificates_fk_rebuild(self):
        """ rebuilding the certificates table on a legacy db logs an info message """
        self._create_legacy_db()
        logger = Mock()
        self.Database(self.db_file).db_update(logger)
        self.assertIn('Database.db_update(): rebuilding certificates table - fixing user_id foreign key',
                      self._info_messages(logger))

    def test_up_to_date_db_update_logs_no_migration_messages(self):
        """ running db_update() on an already-current db logs no per-migration messages """
        db = self.Database(self.db_file)   # construction already migrates to current
        logger = Mock()
        db.db_update(logger)
        messages = self._info_messages(logger)
        self.assertNotIn('Database.db_update(): alter users table - add auth_backend column', messages)
        self.assertNotIn('Database.db_update(): rebuilding certificates table - fixing user_id foreign key', messages)

    def test_legacy_db_existing_users_default_to_local_auth_backend(self):
        """ users created before the migration default to auth_backend 'local' """
        self._create_legacy_db()

        con = sqlite3.connect(self.db_file)
        cur = con.cursor()
        cur.execute('''INSERT INTO users(username, password) VALUES ('foo', 'bar')''')
        con.commit()
        con.close()

        db = self.Database(self.db_file)
        db.db_update()

        self.assertEqual(db.get_user('foo')['auth_backend'], 'local')

    def test_insert_or_update_user_persists_auth_backend(self):
        """ insert_or_update_user() stores and updates the auth_backend value """
        db = self.Database(self.db_file)

        db.insert_or_update_user('foo', 'bar', 'template', '.*', auth_backend='radius')
        self.assertEqual(db.get_user('foo')['auth_backend'], 'radius')

        db.insert_or_update_user('foo', 'bar', 'template', '.*', auth_backend='local')
        self.assertEqual(db.get_user('foo')['auth_backend'], 'local')

    def test_insert_or_update_user_stores_bcrypt_hash(self):
        """ insert_or_update_user() stores a bcrypt hash that verifies against the password """
        import bcrypt
        db = self.Database(self.db_file)

        db.insert_or_update_user('foo', 'bar', 'template', '.*')
        stored = db.get_user('foo')['password']
        self.assertTrue(stored.startswith('$2'))
        self.assertTrue(bcrypt.checkpw(b'bar', stored.encode()))
        self.assertFalse(bcrypt.checkpw(b'wrong', stored.encode()))

    def test_update_user_password_stores_new_bcrypt_hash(self):
        """ update_user_password() replaces the stored hash with a bcrypt hash of the new password """
        import bcrypt
        db = self.Database(self.db_file)

        db.insert_or_update_user('foo', 'bar', 'template', '.*')
        self.assertTrue(db.update_user_password('foo', 'newpass'))

        stored = db.get_user('foo')['password']
        self.assertTrue(stored.startswith('$2'))
        self.assertTrue(bcrypt.checkpw(b'newpass', stored.encode()))
        self.assertFalse(bcrypt.checkpw(b'bar', stored.encode()))

    def test_update_user_password_unknown_user(self):
        """ update_user_password() returns False for a non-existing user """
        db = self.Database(self.db_file)
        self.assertFalse(db.update_user_password('nobody', 'newpass'))

    def test_insert_or_update_user_empty_password_stores_empty_value(self):
        """ insert_or_update_user() stores '' for an empty password (radius users have no local password) """
        db = self.Database(self.db_file)

        db.insert_or_update_user('foo', '', 'template', '.*', auth_backend='radius')
        self.assertEqual(db.get_user('foo')['password'], '')

    def _create_legacy_db(self):
        """ create a pre-migration database (users/certificates only, buggy FK, no housekeeping) """
        con = sqlite3.connect(self.db_file)
        cur = con.cursor()
        cur.execute('''
            CREATE TABLE users
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
        cur.execute('''
            CREATE TABLE certificates
            (
            id INTEGER PRIMARY KEY,
            common_name TEXT,
            valid_from DATETIME,
            valid_to DATETIME,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
            )''')
        con.commit()
        con.close()

if __name__ == '__main__':
    unittest.main()
