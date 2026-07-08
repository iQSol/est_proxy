#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for the tools/db_update.py CLI wrapper """
# pylint: disable=C0415, E0401
import unittest
import sys
import os
import sqlite3
import subprocess
import tempfile

sys.path.insert(0, '.')
sys.path.insert(1, '..')

TOOL = os.path.join(os.path.dirname(__file__), '..', 'tools', 'db_update.py')


class DbUpdateToolTestCases(unittest.TestCase):
    """ test class for the db_update.py command line tool """

    def setUp(self):
        """ setup """
        from est_proxy.version import __dbversion__
        self.dbversion = __dbversion__
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_file = os.path.join(self.tmp_dir.name, 'est_proxy.db')

    def tearDown(self):
        """ teardown """
        self.tmp_dir.cleanup()

    def _run(self):
        """ run the tool against the temp db and return its combined output """
        result = subprocess.run(
            [sys.executable, TOOL, '-d', self.db_file],
            capture_output=True, text=True, check=True)
        # logger_setup() logs via logging.basicConfig -> stderr
        return result.stderr + result.stdout

    def _create_legacy_db(self):
        """ create a pre-migration database (no housekeeping table, so dbversion is None) """
        con = sqlite3.connect(self.db_file)
        cur = con.cursor()
        cur.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
        con.commit()
        con.close()

    def test_legacy_db_reports_version_update(self):
        """ running against a pre-migration db reports the dbversion transition (None -> current) """
        self._create_legacy_db()
        output = self._run()
        self.assertIn('dbversion updated', output)
        self.assertIn('None', output)
        self.assertIn(str(self.dbversion), output)

    def test_up_to_date_db_reports_already_up_to_date(self):
        """ running against an already-current db reports 'already up to date', no update line """
        # a fresh Database() construction already migrates to the current version,
        # so the first tool run has nothing left to do
        self._run()
        output = self._run()
        self.assertIn('already up to date', output)
        self.assertIn(str(self.dbversion), output)
        self.assertNotIn('dbversion updated', output)


if __name__ == '__main__':
    unittest.main()
