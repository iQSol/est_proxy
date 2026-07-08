#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for esthandler """
# pylint: disable= C0415, E0401, R0904, W0201, W0212
import unittest
import sys
import os
import importlib
import io
import base64
import ssl
from hashlib import sha512
from unittest.mock import patch, Mock, MagicMock, mock_open
import bcrypt
from pyrad2.constants import PacketType

sys.path.insert(0, '.')
sys.path.insert(1, '..')
sys.path.insert(2, os.path.dirname(__file__))

import csr_fixtures

class EsthanderTestCases(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_est')
        from est_proxy.est_handler import ESTSrvHandler
        self.esthandler = ESTSrvHandler.__new__(ESTSrvHandler)
        self.esthandler.logger = logging.getLogger('test_est')

    def test_001__cacerts_split(self):
        """ _cacerts_split() two certs """
        ca_certs = """
foo
-----END CERTIFICATE-----
bar
-----END CERTIFICATE-----
"""
        result = ['\nfoo\n-----END CERTIFICATE-----\n', 'bar\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_002__cacerts_split(self):
        """ _cacerts_split() one cert """
        ca_certs = """
foo
-----END CERTIFICATE-----
"""
        result = ['\nfoo\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_003__cacerts_split(self):
        """ _cacerts_split() certs none """
        ca_certs = None
        result = []
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    def test_004__cacerts_split(self):
        """ _cacerts_split() certs is a bogus string """
        ca_certs = 'string'
        result = []
        self.assertEqual(result, self.esthandler._cacerts_split(ca_certs))

    @patch('tempfile.NamedTemporaryFile')
    def test_005__cacerts_dump(self, mock_nf):
        """ _cacerts_dump() two certs """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        obj2 = Mock()
        obj2.name = 'bar_ret'
        mock_nf.side_effect = [obj1, obj2]
        result = ['foo_ret', 'bar_ret']
        self.assertEqual(result, self.esthandler._cacerts_dump(['foo', 'bar']))

    @patch('tempfile.NamedTemporaryFile')
    def test_006_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() one cert """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        result = ['foo_ret']
        self.assertEqual(result, self.esthandler._cacerts_dump(['foo']))

    @patch('tempfile.NamedTemporaryFile')
    def test_007_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() empty list   """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        self.assertFalse(self.esthandler._cacerts_dump([]))

    @patch('tempfile.NamedTemporaryFile')
    def test_008_cacerts_dump(self, mock_nf):
        """ _cacerts_dump() non-list argument (string) """
        obj1 = Mock()
        obj1.name = 'foo_ret'
        mock_nf.side_effect = [obj1]
        self.assertFalse(self.esthandler._cacerts_dump('foo'))

    def test_009__opensslcmd_build(self):
        """ _opensslcmd_build two certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo', 'bar']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo', '--certfile', 'bar']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_010__opensslcmd_build(self):
        """ _opensslcmd_build one certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_011__opensslcmd_build(self):
        """ _opensslcmd_build three certs """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = ['foo1', 'foo2', 'foo3']
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo1', '--certfile', 'foo2', '--certfile', 'foo3']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_012__opensslcmd_build(self):
        """ _opensslcmd_build one certs in list as string """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = 'foo'
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_013__opensslcmd_build(self):
        """ _opensslcmd_build one certs in list as string """
        self.esthandler.openssl_bin = 'openssl'
        file_name_list = b'foo'
        pkcs7_file = 'pkcs7_file'
        result = ['openssl', 'crl2pkcs7', '-nocrl', '-out', 'pkcs7_file', '--certfile', 'foo']
        self.assertEqual(result, self.esthandler._opensslcmd_build(file_name_list, pkcs7_file))

    def test_014___pkcs7_clean(self):
        """ _pkcs7_clean() certs ok """
        pkcs7 = '-----BEGIN PKCS7-----\nfoo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_015___pkcs7_clean(self):
        """ _pkcs7_clean() hast just END tag """
        pkcs7 = 'foo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_016___pkcs7_clean(self):
        """ _pkcs7_clean() just BEGIN tag """
        pkcs7 = '-----BEGIN PKCS7-----\nfoo'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    def test_017___pkcs7_clean(self):
        """ _pkcs7_clean() pcs#7 None """
        pkcs7 = None
        self.assertFalse(self.esthandler._pkcs7_clean(pkcs7))

    def test_018___pkcs7_clean(self):
        """ _pkcs7_clean() pcs#7 int """
        pkcs7 = 8
        self.assertEqual(8, self.esthandler._pkcs7_clean(pkcs7))

    def test_019___pkcs7_clean(self):
        """ _pkcs7_clean() pkcs#7 byte """
        pkcs7 = b'-----BEGIN PKCS7-----\nfoo-----END PKCS7-----'
        result = 'foo'
        self.assertEqual(result, self.esthandler._pkcs7_clean(pkcs7))

    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('subprocess.call')
    def test_020__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean):
        """ _pkcs7_convert() all ok """
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 0
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertEqual('pkcs7_struc', self.esthandler._pkcs7_convert('cacertss'))

    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('subprocess.call')
    def test_021__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean, mock_nf):
        """ _pkcs7_convert() all ok """
        obj1 = Mock()
        obj1.name = 'mock_nf_ret'
        mock_nf.side_effect = [obj1]
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 0
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertEqual('pkcs7_struc', self.esthandler._pkcs7_convert('cacertss'))

    def test_022__pkcs7_convert(self):
        """ _pkcs7_convert() all no cacerts """
        self.esthandler.openssl_bin = 'openssl'
        self.assertFalse(self.esthandler._pkcs7_convert(None))

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    def test_023__pkcs7_convert(self, mock_split, mock_dmp):
        """ _pkcs7_convert() no openssl command defined """
        self.esthandler.openssl_bin = None
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    def test_024__pkcs7_convert(self, mock_split, mock_dmp):
        """ _pkcs7_convert() cert dump run into an error """
        self.esthandler.openssl_bin = 'openssl'
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = []
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open', mock_open(read_data="pkcs7_struc"))
    @patch('est_proxy.est_handler.ESTSrvHandler._tmpfiles_clean')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_dump')
    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_split')
    @patch('subprocess.call')
    def test_025__pkcs7_convert(self, mock_call, mock_split, mock_dmp, mock_clean, mock_nf):
        """ _pkcs7_convert() openssl returns non-zero """
        obj1 = Mock()
        obj1.name = 'mock_nf_ret'
        mock_nf.side_effect = [obj1]
        self.esthandler.openssl_bin = 'openssl'
        mock_call.return_value = 1
        mock_split.return_value = ['foo', 'bar']
        mock_dmp.return_value = ['foo_name', 'bar_name']
        mock_clean.return_value = 0
        self.assertFalse(self.esthandler._pkcs7_convert('cacertss'))

    def test_026__get_process(self):
        """ _get_process() - root path """
        self.esthandler.path = '/'
        self.assertEqual((404, 'text/html', 30, None, b'An unknown error has occured.\n'), self.esthandler._get_process())

    def test_027__get_process(self):
        """ _get_process() - None as path """
        self.esthandler.path = None
        self.assertEqual((404, 'text/html', 30, None, b'An unknown error has occured.\n'), self.esthandler._get_process())

    def test_028__get_process(self):
        """ _get_process() - int as path """
        self.esthandler.path = 13
        self.assertEqual((404, 'text/html', 30, None, b'An unknown error has occured.\n'), self.esthandler._get_process())

    def test_029__get_process(self):
        """ _get_process() - string as path """
        self.esthandler.path = '13'
        self.assertEqual((404, 'text/html', 30, None, b'An unknown error has occured.\n'), self.esthandler._get_process())

    def test_030__get_process(self):
        """ _get_process() - unknown path """
        self.esthandler.path = '/notallowedpath'
        self.assertEqual((404, 'text/html', 30, None, b'An unknown error has occured.\n'), self.esthandler._get_process())

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_get')
    def test_031__get_process(self, mock_caget):
        """ _get_process() - ca certs """
        self.esthandler.path = '/.well-known/est/cacerts'
        mock_caget.return_value = 'foobar'
        self.assertEqual((200, 'application/pkcs7-mime', 6, 'base64', b'foobar'), self.esthandler._get_process())

    @patch('est_proxy.est_handler.ESTSrvHandler._cacerts_get')
    def test_032__get_process(self, mock_caget):
        """ _get_process() - ca certs """
        self.esthandler.path = '/.well-known/est/cacerts'
        mock_caget.return_value = None
        self.assertEqual((500, 'text/html', 0, None, None), self.esthandler._get_process())

    def test_033_set_response(self):
        """ _set_response() - all ok """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, content_type='text/html', clength=100, encoding='utf-8')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Content-Length: 100', self.input)
        self.assertIn('Connection: close', self.input)

    def test_034_set_response(self):
        """ _set_response() - no content length code 500 """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=500, content_type='text/html', clength=0, encoding='utf-8')
        self.assertIn('HTTP/1.1 500 Internal Server Error', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_035_set_response(self):
        """ _set_response() - code 404 """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=404, content_type='text/html', clength=5, encoding='utf-8')
        self.assertIn('HTTP/1.1 404 Not Found', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_036_set_response(self):
        """ _set_response() -  different content length """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, content_type='foo', clength=5, encoding='utf-8')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: foo', self.input)
        self.assertIn('Content-Transfer-Encoding: utf-8', self.input)
        self.assertIn('Connection: close', self.input)

    def test_037_set_response(self):
        """ _set_response() -  different encoding, no content-type """
        def dummy_func(*args):
            self.input = args[0].decode('utf-8')
        mock_wfile = Mock()
        mock_wfile.write = dummy_func
        self.esthandler.requestline = 'requestline'
        self.esthandler.client_address = ('127.0.0.1', 12345)
        self.esthandler.request_version = 'request_version'
        self.esthandler.wfile = mock_wfile
        self.esthandler._set_response(code=200, clength=5, encoding='encoding')
        self.assertIn('HTTP/1.1 200 OK', self.input)
        self.assertIn('Content-Type: text/html', self.input)
        self.assertIn('Content-Transfer-Encoding: encoding', self.input)
        self.assertIn('Connection: close', self.input)

    @patch('est_proxy.est_handler.config_load')
    def test_038_config_load(self, mock_load_cfg):
        """ test _config_load empty dictionary """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._config_load()
        self.assertFalse(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)
        self.assertIn('ERROR:test_est:ESTSrvHandler._config_load(): CAhandler configuration missing in config file', lcm.output)

    @patch('est_proxy.est_handler.config_load')
    def test_039_config_load(self, mock_load_cfg):
        """ test _config_load customized openssl command """
        mock_load_cfg.return_value = {'DEFAULT': {'openssl_bin': 'openssl_bin'}}
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._config_load()
        self.assertFalse(self.esthandler.cahandler)
        self.assertEqual('openssl_bin', self.esthandler.openssl_bin)
        self.assertIn('ERROR:test_est:ESTSrvHandler._config_load(): CAhandler configuration missing in config file', lcm.output)

    @patch('est_proxy.est_handler.config_load')
    def test_040_config_load(self, mock_load_cfg):
        """ test _config_load ca handler config without handler file """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._config_load()
        self.assertFalse(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)
        self.assertIn("ERROR:test_est:ESTSrvHandler._config_load(): default CAhandler could not get loaded. err: No module named 'est_proxy.ca_handler'", lcm.output)

    @patch('importlib.import_module')
    @patch('est_proxy.est_handler.config_load')
    def test_041_config_load(self, mock_load_cfg, mock_import):
        """ test _config_load ca handler config without handler file """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler._config_load()
        self.assertTrue(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)

    @patch('est_proxy.est_handler.config_load')
    def test_042_config_load(self, mock_load_cfg):
        """ test _config_load ca handler handler file configured but both handle_file and default handler failed """
        mock_load_cfg.return_value = {'CAhandler': {'handler_file': 'handler_file', 'foo': 'bar'}}
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._config_load()
        self.assertFalse(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)
        self.assertIn("ERROR:test_est:ESTSrvHandler._config_load(): CAhandler handler_file could not get loaded. with error: No module named 'handler_file'\nLoading default hander...", lcm.output)
        self.assertIn("ERROR:test_est:ESTSrvHandler._config_load():  Loading default handler failed.", lcm.output)

    @patch('importlib.import_module')
    @patch('est_proxy.est_handler.config_load')
    def test_043_config_load(self, mock_load_cfg, mock_import):
        """ test _config_load ca handler config without handler file """
        mock_load_cfg.return_value = {'CAhandler': {'handler_file': 'handler_file', 'foo': 'bar'}}
        mockresponse1 = Exception('exc_cahandlerconfigload')
        mockresponse2 = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        mock_import.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._config_load()
        self.assertTrue(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)
        self.assertIn("ERROR:test_est:ESTSrvHandler._config_load(): CAhandler handler_file could not get loaded. with error: exc_cahandlerconfigload\nLoading default hander...", lcm.output)

    @patch('importlib.import_module')
    @patch('est_proxy.est_handler.config_load')
    def test_044_config_load(self, mock_load_cfg, mock_import):
        """ test _config_load ca handler confighandler file could get successfully loaded """
        mock_load_cfg.return_value = {'CAhandler': {'handler_file': 'handler_file', 'foo': 'bar'}}
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler._config_load()
        self.assertTrue(self.esthandler.cahandler)
        self.assertEqual('openssl', self.esthandler.openssl_bin)

    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    def test_045__post_process(self, mock_auth):
        """ _post_process() - root path """
        self.esthandler.path = '/'
        mock_auth.return_value = False
        self.assertEqual((401, None, 48, None, b'The server was unable to authorize the request.\n'), self.esthandler._post_process('data'))

    @patch('est_proxy.est_handler.ESTSrvHandler._check_csr_data')
    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    def test_046__post_process(self, mock_auth, mock_csr):
        """ _post_process() - root path """
        self.esthandler.path = '/'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        mock_csr.return_value = True
        self.assertEqual((400, None, 30, None, b'An unknown error has occured.\n'), self.esthandler._post_process(b'data'))

    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    def test_047__post_process(self, mock_auth):
        """ _post_process() - enroll but no data """
        self.esthandler.path = '/.well-known/est/simpleenroll'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        self.assertEqual((400, None, 23, None, b'No data had been send.\n'), self.esthandler._post_process(None))

    @patch('est_proxy.est_handler.ESTSrvHandler._check_csr_data')
    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    def test_048__post_process(self, mock_auth, mock_csr):
        """ _post_process() - enroll but data to a wrong url """
        self.esthandler.path = '/foobadoo'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        mock_csr.return_value = True
        self.assertEqual((400, None, 30, None, b'An unknown error has occured.\n'), self.esthandler._post_process(b'data'))

    @patch('est_proxy.est_handler.ESTSrvHandler._check_csr_data')
    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    @patch('est_proxy.est_handler.ESTSrvHandler._cert_enroll')
    def test_049__post_process(self, mock_enroll, mock_auth, mock_csr):
        """ _post_process() - enroll returns an error """
        self.esthandler.path = '/.well-known/est/simplereenroll'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        mock_csr.return_value = True
        mock_enroll.return_value = ('error', 'cert')
        self.assertEqual((500, None, 51, None, b'A problem ocurred while enrolling the certificate.\n'), self.esthandler._post_process(b'data'))

    @patch('est_proxy.est_handler.ESTSrvHandler._check_csr_data')
    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    @patch('est_proxy.est_handler.ESTSrvHandler._cert_enroll')
    def test_050__post_process(self, mock_enroll, mock_auth, mock_csr):
        """ _post_process() - enroll succeeds """
        self.esthandler.path = '/.well-known/est/simplereenroll'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        mock_csr.return_value = True
        mock_enroll.return_value = (None, 'cert')
        self.assertEqual((200, 'application/pkcs7-mime; smime-type=certs-only', 4, 'base64', b'cert'), self.esthandler._post_process(b'data'))

    @patch('est_proxy.est_handler.ESTSrvHandler._auth_check')
    def test_050a__post_process(self, mock_auth):
        """ _post_process() - pem header followed by invalid utf-8 returns a 400 instead of raising """
        self.esthandler.path = '/.well-known/est/simpleenroll'
        self.esthandler.user = {'id': 1}
        mock_auth.return_value = True
        with self.assertLogs('test_est', level='INFO') as lcm:
            (code, _content_type, _content_length, _encoding, content) = self.esthandler._post_process(b'-----BEGIN CERTIFICATE REQUEST-----\n\xff\xfe')
        self.assertEqual(400, code)
        self.assertEqual(b'A problem ocurred while checking the CSR. View the EST proxy log for more information!\n', content)
        self.assertIn('ERROR:test_est: => Aborted - Could not load CSR.', lcm.output)

    def test_051__cert_enroll(self):
        """ _cert_enroll() without csr """
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(('no CSR submittted', None), self.esthandler._cert_enroll(None))
        self.assertIn('ERROR:test_est:ESTSrvHandler._cert_enroll(): no csr submitted', lcm.output)

    def test_052__cert_enroll(self):
        """ _cert_enroll() error returned """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler.cfg_file = None
        self.esthandler.user = {'id': 1, 'template': None}
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        self.esthandler.cahandler.enroll = Mock(return_value=['error', 'cert', 'poll_identifier'])
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(('error', None), self.esthandler._cert_enroll('data'))
        self.assertIn('ERROR:test_est:ESTSrvHandler._cert_enroll(): error', lcm.output)

    def test_053__cert_enroll(self):
        """ _cert_enroll() error returned """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler.cfg_file = None
        self.esthandler.user = {'id': 1, 'template': None}
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        self.esthandler.cahandler.enroll = Mock(return_value=[None, None, 'poll_identifier'])
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(('No error but no cert returned', None), self.esthandler._cert_enroll('data'))
        self.assertIn('ERROR:test_est:ESTSrvHandler._cert_enroll(): No error but no cert returned', lcm.output)

    def test_053a__cert_enroll(self):
        """ _cert_enroll() with the mswcce handler and incomplete config returns an error instead of raising """
        ca_handler_module = importlib.import_module('examples.ca_handler.mswcce_ca_handler')
        self.esthandler.cfg_file = None
        self.esthandler.user = {'id': 1, 'template': None}
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(('Config incomplete', None), self.esthandler._cert_enroll('data'))
        self.assertIn('ERROR:test_est:ESTSrvHandler._cert_enroll(): Config incomplete', lcm.output)

    @patch('est_proxy.est_handler.get_certificate_information')
    @patch('est_proxy.est_handler.ESTSrvHandler._pkcs7_convert')
    def test_054__cert_enroll(self, mock_convert, mock_certinfo):
        """ _cert_enroll() all ok """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler.cfg_file = None
        self.esthandler.user = {'id': 1, 'template': None}
        self.esthandler.database = Mock()
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        self.esthandler.cahandler.enroll = Mock(return_value=[None, 'cert', 'poll_identifier'])
        mock_certinfo.return_value = {'common_name': 'cn', 'valid_from': 'from', 'valid_to': 'to'}
        mock_convert.return_value = 'pkcs7'
        self.assertEqual((None, 'pkcs7'), self.esthandler._cert_enroll('data'))
        self.esthandler.database.insert_or_update_certificate.assert_called_with('cn', 'from', 'to', 1)

    def test_055__cacerts_get(self):
        """ _cacerts_get() handler returns no cacerts """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        self.esthandler.cahandler.ca_certs_get = Mock(return_value=None)
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(None, self.esthandler._cacerts_get())
        self.assertIn('ERROR:test_est:ESTSrvHandler._cacerts_get(): no cacerts returned from handler', lcm.output)

    @patch('est_proxy.est_handler.ESTSrvHandler._pkcs7_convert')
    def test_056__cacerts_get(self, mock_convert):
        """ _cacerts_get() converts returned cacerts to pkcs#7 """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.esthandler.cahandler = ca_handler_module.CAhandler
        self.esthandler.cahandler._config_load = Mock()
        self.esthandler.cahandler.ca_certs_get = Mock(return_value='cacert')
        mock_convert.return_value = 'pkcs7'
        self.assertEqual('pkcs7', self.esthandler._cacerts_get())

    def test_057__auth_check(self):
        """ _auth_check() neither nginx client verification nor basic auth """
        self.esthandler.headers = {}
        self.assertFalse(self.esthandler._auth_check())

    @patch('est_proxy.est_handler.ESTSrvHandler._nginx_auth_check')
    def test_058__auth_check(self, mock_nginx):
        """ _auth_check() nginx client verification """
        self.esthandler.headers = {'X-SSL-Verified': 'SUCCESS'}
        mock_nginx.return_value = True
        self.assertTrue(self.esthandler._auth_check())
        self.assertTrue(mock_nginx.called)

    @patch('est_proxy.est_handler.ESTSrvHandler._basic_auth_check')
    def test_059__auth_check(self, mock_basic):
        """ _auth_check() basic auth """
        self.esthandler.headers = {'Authorization': 'Basic Zm9vOmJhcg=='}
        mock_basic.return_value = True
        self.assertTrue(self.esthandler._auth_check())
        self.assertTrue(mock_basic.called)

    @patch('est_proxy.est_handler.ESTSrvHandler._basic_auth_check')
    @patch('est_proxy.est_handler.ESTSrvHandler._nginx_auth_check')
    def test_060__auth_check(self, mock_nginx, mock_basic):
        """ _auth_check() nginx client verification fails - fallback to basic auth """
        self.esthandler.headers = {'X-SSL-Verified': 'NONE', 'Authorization': 'Basic Zm9vOmJhcg=='}
        mock_nginx.return_value = False
        mock_basic.return_value = True
        self.assertTrue(self.esthandler._auth_check())
        self.assertTrue(mock_nginx.called)
        self.assertTrue(mock_basic.called)

    @patch('est_proxy.est_handler.ESTSrvHandler._basic_auth_check')
    def test_060a__auth_check(self, mock_basic):
        """ _auth_check() authorization header with a non-basic scheme is ignored """
        self.esthandler.headers = {'Authorization': 'Bearer foo'}
        mock_basic.return_value = True
        self.assertFalse(self.esthandler._auth_check())
        self.assertFalse(mock_basic.called)

    @patch('os.remove')
    def test_061__tmpfiles_clean(self, mock_remove):
        """ __tmpfiles_clean """
        file_list = ['foo', 'bar']
        mock_remove.return_value = True
        self.esthandler._tmpfiles_clean(file_list)

    @patch('os.remove')
    def test_062_tmpfiles_clean(self, mock_remove):
        """ __tmpfiles_clean exception for all files """
        file_list = ['foo', 'bar']
        mock_remove.side_effect = Exception('_tmpfiles_clean')
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._tmpfiles_clean(file_list)
        self.assertIn('ERROR:test_est:ESTSrvHandler._tmpfiles_clean() failed for foo with error: _tmpfiles_clean', lcm.output)
        self.assertIn('ERROR:test_est:ESTSrvHandler._tmpfiles_clean() failed for bar with error: _tmpfiles_clean', lcm.output)

    @patch('os.remove')
    def test_063_tmpfiles_clean(self, mock_remove):
        """ __tmpfiles_clean exception for last file """
        file_list = ['foo', 'bar']
        mock_remove.side_effect = [True, Exception('_tmpfiles_clean')]
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._tmpfiles_clean(file_list)
        self.assertIn('ERROR:test_est:ESTSrvHandler._tmpfiles_clean() failed for bar with error: _tmpfiles_clean', lcm.output)

    @patch('os.remove')
    def test_064_tmpfiles_clean(self, mock_remove):
        """ __tmpfiles_clean exception for last file """
        file_list = ['foo', 'bar']
        mock_remove.side_effect = [Exception('_tmpfiles_clean'), True]
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler._tmpfiles_clean(file_list)
        self.assertIn('ERROR:test_est:ESTSrvHandler._tmpfiles_clean() failed for foo with error: _tmpfiles_clean', lcm.output)

    @patch('est_proxy.est_handler.ESTSrvHandler._get_process')
    def test_065_do_get(self, mock_process):
        """ test do get """
        mock_process.return_value = ['code', 'content_type', 'content_length', 'encoding', 'content']
        self.esthandler.client_address = ('127.0.0.1', 8080)
        self.esthandler.path = '/'
        self.esthandler.requestline = 'requestline'
        self.esthandler.request_version = 'HTTP/0.9'
        self.esthandler.wfile = Mock()
        self.assertFalse(self.esthandler.do_GET())

    @patch('est_proxy.est_handler.Database')
    def test_066__init__(self, mock_database):
        """ test __init__ exception when parsing cfg_file """
        request = Mock()
        request.makefile.return_value = io.BytesIO(b"GET /")
        # request.raw_requestline.return_value = 'fooooo'
        client_address = 'client_address'
        server_address = 'server_address'
        self.esthandler.__init__(request, client_address, server_address)
        self.assertEqual('est_proxy.cfg', self.esthandler.cfg_file)

    @patch('est_proxy.est_handler.Database')
    def test_067__init__(self, mock_database):
        """ test __init__ parsing cfg_file """
        request = Mock()
        request.makefile.return_value = io.BytesIO(b"GET /")
        # request.raw_requestline.return_value = 'fooooo'
        client_address = 'client_address'
        server_address = Mock()
        server_address.cfg_file = 'foo.cfg'
        self.esthandler.__init__(request, client_address, server_address)
        self.assertEqual('foo.cfg', self.esthandler.cfg_file)

    @patch('est_proxy.est_handler.Database')
    def test_068__init__(self, mock_database):
        """ test __init__ falls back to default cfg_file when args are missing """
        self.esthandler.__init__()
        self.assertEqual('est_proxy.cfg', self.esthandler.cfg_file)

    @patch('est_proxy.est_handler.ESTSrvHandler._post_process')
    def test_069_do_post(self, mock_process):
        """ test do_POST with a Content-Length body """
        mock_process.return_value = ['code', 'content_type', 'content_length', 'encoding', 'content']
        self.esthandler.client_address = ('127.0.0.1', 8080)
        self.esthandler.path = '/'
        self.esthandler.requestline = 'requestline'
        self.esthandler.request_version = 'HTTP/0.9'
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.read = Mock(return_value=b'123456789012345')
        self.esthandler.wfile = Mock()
        self.esthandler.headers = {'Content-Length': 15}
        self.assertFalse(self.esthandler.do_POST())

    @patch('est_proxy.est_handler.ESTSrvHandler._post_process')
    def test_070_do_post(self, mock_process):
        """ test do_POST with a zero-length Content-Length """
        mock_process.return_value = ['code', 'content_type', 'content_length', 'encoding', 'content']
        self.esthandler.client_address = ('127.0.0.1', 8080)
        self.esthandler.path = '/'
        self.esthandler.requestline = 'requestline'
        self.esthandler.request_version = 'HTTP/0.9'
        self.esthandler.rfile = Mock()
        self.esthandler.wfile = Mock()
        self.esthandler.headers = {'Content-Length': 0}
        self.assertFalse(self.esthandler.do_POST())

    @patch('est_proxy.est_handler.ESTSrvHandler._post_process')
    def test_071_do_post(self, mock_process):
        """ test do_POST with a chunked request body """
        mock_process.return_value = ['code', 'content_type', 'content_length', 'encoding', 'content']
        self.esthandler.client_address = ('127.0.0.1', 8080)
        self.esthandler.path = '/'
        self.esthandler.requestline = 'requestline'
        self.esthandler.request_version = 'HTTP/0.9'
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'11\r\n', b'\r\n', b'0\r\n', b'\r\n']
        self.esthandler.rfile.read = Mock(return_value=b'12345678901234567')
        self.esthandler.wfile = Mock()
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.assertFalse(self.esthandler.do_POST())
        mock_process.assert_called_with(b'12345678901234567')

    def test_071a__chunked_body_read_multiple_chunks(self):
        """ _chunked_body_read() reassembles multiple chunks even when a chunk boundary splits a line """
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'3\r\n', b'\r\n', b'4\r\n', b'\r\n', b'0\r\n', b'\r\n']
        self.esthandler.rfile.read = Mock()
        self.esthandler.rfile.read.side_effect = [b'foo', b'obar']
        self.assertEqual(b'fooobar', self.esthandler._chunked_body_read())

    def test_071b__chunked_body_read_chunk_extension(self):
        """ _chunked_body_read() tolerates chunk extensions on the size line (RFC 7230) """
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'3;name=val\r\n', b'\r\n', b'0\r\n', b'\r\n']
        self.esthandler.rfile.read = Mock(return_value=b'foo')
        self.assertEqual(b'foo', self.esthandler._chunked_body_read())

    def test_071c__body_read_chunked_garbage_size_line(self):
        """ _body_read() returns a 400 error on a non-hex chunk size line """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'nohex\r\n']
        self.assertEqual(((400, 'Malformed chunked request body.\n'), None), self.esthandler._body_read())

    def test_071d__body_read_chunked_too_large(self):
        """ _body_read() returns a 413 error if the chunked body exceeds MAX_BODY_SIZE """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'ffffff\r\n']
        self.assertEqual(((413, 'Request body too large.\n'), None), self.esthandler._body_read())

    def test_071e__body_read_content_length_too_large(self):
        """ _body_read() rejects an oversized Content-Length before reading the body """
        self.esthandler.headers = {'Content-Length': '100000'}
        self.esthandler.rfile = Mock()
        self.assertEqual(((413, 'Request body too large.\n'), None), self.esthandler._body_read())
        self.assertFalse(self.esthandler.rfile.read.called)

    def test_071f__body_read_invalid_content_length(self):
        """ _body_read() returns a 400 error on a non-numeric Content-Length header """
        self.esthandler.headers = {'Content-Length': 'foo'}
        self.esthandler.rfile = Mock()
        self.assertEqual(((400, 'Invalid Content-Length header.\n'), None), self.esthandler._body_read())

    def test_071g__body_read_no_framing(self):
        """ _body_read() without Content-Length and Transfer-Encoding returns no data (regression: crashed before) """
        self.esthandler.headers = {}
        self.esthandler.rfile = Mock()
        self.assertEqual((None, None), self.esthandler._body_read())

    def test_071h__body_read_chunked_premature_end(self):
        """ _body_read() returns a 400 error if the connection ends inside a chunk """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'5\r\n']
        self.esthandler.rfile.read = Mock()
        self.esthandler.rfile.read.side_effect = [b'ab', b'']
        self.assertEqual(((400, 'Malformed chunked request body.\n'), None), self.esthandler._body_read())

    def test_071i__body_read_chunked_missing_terminator(self):
        """ _body_read() returns a 400 error if a chunk is not terminated with CRLF """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'3\r\n', b'XX\r\n']
        self.esthandler.rfile.read = Mock(return_value=b'foo')
        self.assertEqual(((400, 'Malformed chunked request body.\n'), None), self.esthandler._body_read())

    def test_071j__chunked_body_read_short_reads(self):
        """ _chunked_body_read() reassembles a chunk delivered in several short reads (unbuffered rfile) """
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'5\r\n', b'\r\n', b'0\r\n', b'\r\n']
        self.esthandler.rfile.read = Mock()
        self.esthandler.rfile.read.side_effect = [b'ab', b'cde']
        self.assertEqual(b'abcde', self.esthandler._chunked_body_read())

    def test_071k__body_read_content_length_short_read(self):
        """ _body_read() returns a 400 error if the connection ends before Content-Length bytes arrived """
        self.esthandler.headers = {'Content-Length': '10'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.read = Mock()
        self.esthandler.rfile.read.side_effect = [b'12345', b'']
        self.assertEqual(((400, 'Malformed request body.\n'), None), self.esthandler._body_read())

    def test_071l__body_read_content_length_and_transfer_encoding(self):
        """ _body_read() rejects ambiguous framing with both Content-Length and Transfer-Encoding """
        self.esthandler.headers = {'Content-Length': '5', 'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.assertEqual(((400, 'Both Content-Length and Transfer-Encoding present.\n'), None), self.esthandler._body_read())
        self.assertFalse(self.esthandler.rfile.read.called)

    def test_071m__body_read_chunked_lax_hex_rejected(self):
        """ _body_read() rejects chunk sizes int() would accept but RFC 7230 does not ("0x5") """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'0x5\r\n']
        self.assertEqual(((400, 'Malformed chunked request body.\n'), None), self.esthandler._body_read())

    def test_071n__body_read_chunked_trailer_flood(self):
        """ _body_read() returns a 400 error instead of consuming unlimited trailer lines """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'0\r\n'] + [b'X-Trailer: x\r\n'] * 200
        self.assertEqual(((400, 'Malformed chunked request body.\n'), None), self.esthandler._body_read())

    def test_071o__body_read_chunked_cumulative_too_large(self):
        """ _body_read() returns a 413 error if the chunks together exceed MAX_BODY_SIZE """
        self.esthandler.headers = {'Transfer-Encoding': 'chunked'}
        self.esthandler.rfile = Mock()
        self.esthandler.rfile.readline.side_effect = [b'8000\r\n', b'\r\n', b'8001\r\n']
        self.esthandler.rfile.read = Mock(return_value=b'a' * 0x8000)
        self.assertEqual(((413, 'Request body too large.\n'), None), self.esthandler._body_read())

    def test_071p__log_message(self):
        """ log_message() routes stdlib request lines through the est_proxy logger """
        self.esthandler.client_address = ('127.0.0.1', 8080)
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.esthandler.log_message('"%s" %s %s', 'POST /foo HTTP/1.0', '400', '-')
        self.assertIn('INFO:test_est:"POST /foo HTTP/1.0" 400 -', lcm.output)

    def _basic_auth_header(self, username, password):
        """ build a Basic auth header value for the given credentials """
        credentials = '{0}:{1}'.format(username, password)
        return 'Basic ' + base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

    def test_072__basic_auth_check_local_backend_success(self):
        """ _basic_auth_check() auth_backend 'local' with correct password (legacy sha512 hash, fallback path) """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': sha512(b'bar').hexdigest()})
        self.assertTrue(self.esthandler._basic_auth_check())

    def test_073__basic_auth_check_local_backend_wrong_password(self):
        """ _basic_auth_check() auth_backend 'local' with wrong password (legacy sha512 hash, fallback path) """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'wrong')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': sha512(b'bar').hexdigest()})
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074__basic_auth_check_unknown_user(self):
        """ _basic_auth_check() username not in database """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value=None)
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074a__basic_auth_check_local_backend_bcrypt_success(self):
        """ _basic_auth_check() auth_backend 'local' with correct password against a bcrypt hash """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        bcrypt_hash = bcrypt.hashpw(b'bar', bcrypt.gensalt()).decode()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': bcrypt_hash})
        self.assertTrue(self.esthandler._basic_auth_check())

    def test_074b__basic_auth_check_local_backend_bcrypt_wrong_password(self):
        """ _basic_auth_check() auth_backend 'local' with wrong password against a bcrypt hash """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'wrong')}
        self.esthandler.database = Mock()
        bcrypt_hash = bcrypt.hashpw(b'bar', bcrypt.gensalt()).decode()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': bcrypt_hash})
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074c__basic_auth_check_local_backend_empty_hash_rejected(self):
        """ _basic_auth_check() an empty stored password value never authenticates (radius users store '') """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', '')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': ''})
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074d__local_auth_check_malformed_bcrypt_hash_rejected(self):
        """ _local_auth_check() fails closed on a malformed $2 hash """
        self.assertFalse(self.esthandler._local_auth_check('bar', '$2b$garbage'))

    def test_074f__basic_auth_check_password_with_colon(self):
        """ _basic_auth_check() passwords may contain colons (RFC 7617) """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'ba:r')}
        self.esthandler.database = Mock()
        bcrypt_hash = bcrypt.hashpw(b'ba:r', bcrypt.gensalt()).decode()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': bcrypt_hash})
        self.assertTrue(self.esthandler._basic_auth_check())

    def test_074g__basic_auth_check_malformed_base64(self):
        """ _basic_auth_check() fails closed on undecodable base64 credentials """
        self.esthandler.headers = {'Authorization': 'Basic !!!notbase64!!!'}
        self.esthandler.database = Mock()
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074h__basic_auth_check_credentials_without_colon(self):
        """ _basic_auth_check() fails closed on credentials without a colon separator """
        self.esthandler.headers = {'Authorization': 'Basic ' + base64.b64encode(b'foobar').decode('utf-8')}
        self.esthandler.database = Mock()
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074i__basic_auth_check_header_without_credentials(self):
        """ _basic_auth_check() fails closed on an Authorization header without credentials """
        self.esthandler.headers = {'Authorization': 'Basic'}
        self.esthandler.database = Mock()
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_074j__basic_auth_check_sha512_rehash_on_login(self):
        """ _basic_auth_check() successful login against a legacy sha512 hash migrates it to bcrypt """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': sha512(b'bar').hexdigest()})
        self.assertTrue(self.esthandler._basic_auth_check())
        self.esthandler.database.update_user_password.assert_called_with('foo', 'bar')

    def test_074k__basic_auth_check_bcrypt_no_rehash(self):
        """ _basic_auth_check() login against a bcrypt hash does not trigger a rehash """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        bcrypt_hash = bcrypt.hashpw(b'bar', bcrypt.gensalt()).decode()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': bcrypt_hash})
        self.assertTrue(self.esthandler._basic_auth_check())
        self.assertFalse(self.esthandler.database.update_user_password.called)

    def test_074l__basic_auth_check_sha512_wrong_password_no_rehash(self):
        """ _basic_auth_check() failed login against a legacy sha512 hash does not rehash """
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'wrong')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'local', 'password': sha512(b'bar').hexdigest()})
        self.assertFalse(self.esthandler._basic_auth_check())
        self.assertFalse(self.esthandler.database.update_user_password.called)

    def test_074m__nginx_auth_check_garbage_cert(self):
        """ _nginx_auth_check() fails closed on an unparseable X-CLIENT-Cert header """
        self.esthandler.client_certificate = None
        self.esthandler.headers = {'X-SSL-Verified': 'SUCCESS', 'X-CLIENT-Cert': 'garbage'}
        self.esthandler.database = Mock()
        self.assertFalse(self.esthandler._nginx_auth_check())
        self.assertIsNone(self.esthandler.client_certificate)

    def test_074n__nginx_auth_check_missing_cert_header(self):
        """ _nginx_auth_check() fails closed if X-CLIENT-Cert is missing """
        self.esthandler.client_certificate = None
        self.esthandler.headers = {'X-SSL-Verified': 'SUCCESS'}
        self.esthandler.database = Mock()
        self.assertFalse(self.esthandler._nginx_auth_check())

    def test_074e__local_auth_check_none_hash_rejected(self):
        """ _local_auth_check() fails closed on a NULL stored password """
        self.assertFalse(self.esthandler._local_auth_check('bar', None))

    @patch('est_proxy.est_handler.ESTSrvHandler._radius_auth_check')
    def test_075__basic_auth_check_radius_backend_dispatch(self, mock_radius):
        """ _basic_auth_check() auth_backend 'radius' calls _radius_auth_check() instead of the local hash check """
        mock_radius.return_value = True
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'radius', 'password': 'unused'})
        self.assertTrue(self.esthandler._basic_auth_check())
        mock_radius.assert_called_with('foo', 'bar')

    @patch('est_proxy.est_handler.ESTSrvHandler._radius_auth_check')
    def test_076__basic_auth_check_radius_backend_denied(self, mock_radius):
        """ _basic_auth_check() auth_backend 'radius' denied by radius server """
        mock_radius.return_value = False
        self.esthandler.headers = {'Authorization': self._basic_auth_header('foo', 'bar')}
        self.esthandler.database = Mock()
        self.esthandler.database.get_user = Mock(return_value={'auth_backend': 'radius', 'password': 'unused'})
        self.assertFalse(self.esthandler._basic_auth_check())

    def test_077__radius_auth_check_no_radius_cfg(self):
        """ _radius_auth_check() fails closed if [RADIUS] is not configured """
        self.esthandler.radius_cfg = None
        self.assertFalse(self.esthandler._radius_auth_check('foo', 'bar'))

    def _udp_radius_cfg(self):
        """ a plain-udp [RADIUS] config dict """
        return {'proto': 'udp', 'server': '127.0.0.1', 'port': 1812, 'secret': 'secret', 'timeout': 5, 'retries': 1, 'nas_identifier': 'est_proxy'}

    def _radsec_radius_cfg(self):
        """ a radsec [RADIUS] config dict (pyrad2 RadSecClient keys) """
        return {'proto': 'radsec', 'server': '127.0.0.1', 'port': 2083, 'secret': 'radsec', 'timeout': 5, 'retries': 1, 'nas_identifier': 'est_proxy',
                'certfile': '/client.crt', 'keyfile': '/client.key', 'certfile_server': '/ca.pem',
                'check_hostname': True, 'min_tls_version': '1.3'}

    def _mock_udp_client(self, mock_client_cls, reply_code):
        """ wire a mocked pyrad2 UDP Client returning a reply with the given code """
        mock_client = mock_client_cls.return_value
        # MagicMock: the request packet must support item assignment (request['User-Password'] = ...)
        mock_request = MagicMock()
        mock_request.pw_crypt = Mock(return_value=b'encrypted')
        mock_client.create_auth_packet = Mock(return_value=mock_request)
        mock_client.send_packet = Mock(return_value=Mock(code=reply_code))
        return mock_client

    def _mock_radsec_client(self, mock_radsec_cls, reply_code):
        """ wire a mocked pyrad2 RadSecClient whose send_packet is an awaitable coroutine """
        mock_client = mock_radsec_cls.return_value
        # MagicMock: the request packet must support item assignment (request['User-Password'] = ...)
        mock_request = MagicMock()
        mock_request.pw_crypt = Mock(return_value=b'encrypted')
        mock_client.create_auth_packet = Mock(return_value=mock_request)

        async def _send_packet(_pkt):
            return Mock(code=reply_code)
        mock_client.send_packet = _send_packet
        return mock_client

    @patch('est_proxy.est_handler.Client')
    def test_078__radius_auth_check_access_accept(self, mock_client_cls):
        """ _radius_auth_check() returns True on AccessAccept (udp) """
        self.esthandler.radius_cfg = self._udp_radius_cfg()
        self._mock_udp_client(mock_client_cls, PacketType.AccessAccept)
        self.assertTrue(self.esthandler._radius_auth_check('foo', 'bar'))

    @patch('est_proxy.est_handler.Client')
    def test_079__radius_auth_check_access_reject(self, mock_client_cls):
        """ _radius_auth_check() returns False on AccessReject (udp) """
        self.esthandler.radius_cfg = self._udp_radius_cfg()
        self._mock_udp_client(mock_client_cls, PacketType.AccessReject)
        self.assertFalse(self.esthandler._radius_auth_check('foo', 'bar'))

    @patch('est_proxy.est_handler.Client')
    def test_080__radius_auth_check_exception_fails_closed(self, mock_client_cls):
        """ _radius_auth_check() fails closed on connection errors/timeouts (udp) """
        self.esthandler.radius_cfg = self._udp_radius_cfg()
        mock_client_cls.side_effect = Exception('timed out')
        self.assertFalse(self.esthandler._radius_auth_check('foo', 'bar'))

    @patch('est_proxy.est_handler.RadSecClient')
    def test_081__radius_auth_check_radsec_access_accept(self, mock_radsec_cls):
        """ _radius_auth_check() proto=radsec builds a RadSecClient and returns True on AccessAccept """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self._mock_radsec_client(mock_radsec_cls, PacketType.AccessAccept)
        self.assertTrue(self.esthandler._radius_auth_check('foo', 'bar'))
        self.assertTrue(mock_radsec_cls.called)

    @patch('est_proxy.est_handler.RadSecClient')
    def test_082__radius_auth_check_radsec_access_reject(self, mock_radsec_cls):
        """ _radius_auth_check() proto=radsec returns False on AccessReject """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self._mock_radsec_client(mock_radsec_cls, PacketType.AccessReject)
        self.assertFalse(self.esthandler._radius_auth_check('foo', 'bar'))

    @patch('est_proxy.est_handler.Client')
    @patch('est_proxy.est_handler.RadSecClient')
    def test_083__radius_auth_check_radsec_does_not_use_udp_client(self, mock_radsec_cls, mock_client_cls):
        """ _radius_auth_check() proto=radsec never constructs the udp Client """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self._mock_radsec_client(mock_radsec_cls, PacketType.AccessAccept)
        self.esthandler._radius_auth_check('foo', 'bar')
        self.assertFalse(mock_client_cls.called)

    @patch('est_proxy.est_handler.RadSecClient')
    def test_084__radius_auth_check_radsec_exception_fails_closed(self, mock_radsec_cls):
        """ _radius_auth_check() proto=radsec fails closed on tls/connection errors """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        mock_radsec_cls.side_effect = Exception('tls handshake failed')
        self.assertFalse(self.esthandler._radius_auth_check('foo', 'bar'))

    @patch('est_proxy.est_handler.RadSecClient')
    def test_084a__radsec_client_passes_tls_options(self, mock_radsec_cls):
        """ _radsec_client() passes min_tls_version to the RadSecClient """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self.esthandler.radius_cfg['min_tls_version'] = '1.2'
        self.esthandler._radsec_client()
        _args, kwargs = mock_radsec_cls.call_args
        self.assertEqual(kwargs['minimum_tls_version'], ssl.TLSVersion.TLSv1_2)

    @patch('est_proxy.est_handler.RadSecClient')
    def test_084b__radsec_client_tls_defaults(self, mock_radsec_cls):
        """ _radsec_client() defaults to TLS 1.3 minimum """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self.esthandler._radsec_client()
        _args, kwargs = mock_radsec_cls.call_args
        self.assertEqual(kwargs['minimum_tls_version'], ssl.TLSVersion.TLSv1_3)

    @patch('est_proxy.est_handler.RadSecClient')
    def test_084c__radsec_client_passes_secret(self, mock_radsec_cls):
        """ _radsec_client() passes the configured secret through encoded """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        self.esthandler.radius_cfg['secret'] = 'mysecret'
        self.esthandler._radsec_client()
        _args, kwargs = mock_radsec_cls.call_args
        self.assertEqual(kwargs['secret'], b'mysecret')

    @patch('est_proxy.est_handler.Client')
    def test_084d__udp_client_passes_config(self, mock_client_cls):
        """ _udp_client() constructs the pyrad2 Client from the udp config (secret encoded) """
        self.esthandler.radius_cfg = self._udp_radius_cfg()
        self.esthandler._udp_client()
        _args, kwargs = mock_client_cls.call_args
        self.assertEqual(kwargs['server'], '127.0.0.1')
        self.assertEqual(kwargs['authport'], 1812)
        self.assertEqual(kwargs['secret'], b'secret')
        self.assertEqual(kwargs['retries'], 1)
        self.assertEqual(kwargs['timeout'], 5)

    def test_084e__radius_send_builds_access_request_packet(self):
        """ _radius_send() builds an Access-Request with the NAS identifier and encrypted password (udp) """
        self.esthandler.radius_cfg = self._udp_radius_cfg()
        mock_client = MagicMock()
        mock_request = MagicMock()
        mock_request.pw_crypt = Mock(return_value=b'encrypted')
        mock_client.create_auth_packet = Mock(return_value=mock_request)
        mock_client.send_packet = Mock(return_value='reply')
        result = self.esthandler._radius_send(mock_client, 'foo', 'bar')
        mock_client.create_auth_packet.assert_called_with(code=PacketType.AccessRequest, User_Name='foo', NAS_Identifier='est_proxy')
        mock_request.pw_crypt.assert_called_with('bar')
        mock_request.__setitem__.assert_called_with('User-Password', b'encrypted')
        mock_client.send_packet.assert_called_with(mock_request)
        self.assertEqual('reply', result)

    def test_084f__radius_send_radsec_runs_coroutine(self):
        """ _radius_send() proto=radsec awaits the coroutine returned by send_packet via asyncio.run """
        self.esthandler.radius_cfg = self._radsec_radius_cfg()
        mock_client = MagicMock()
        mock_request = MagicMock()
        mock_request.pw_crypt = Mock(return_value=b'encrypted')
        mock_client.create_auth_packet = Mock(return_value=mock_request)

        async def _send_packet(_pkt):
            return 'radsec-reply'
        mock_client.send_packet = _send_packet
        self.assertEqual('radsec-reply', self.esthandler._radius_send(mock_client, 'foo', 'bar'))

    def test_085__radius_config_load_udp(self):
        """ _radius_config_load() parses a plain udp section """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'secret': 's3cr3t'}}
        result = self.esthandler._radius_config_load(config_dic)
        self.assertEqual(result['proto'], 'udp')
        self.assertEqual(result['server'], '1.2.3.4')
        self.assertEqual(result['secret'], 's3cr3t')
        self.assertEqual(result['port'], 1812)

    def test_086__radius_config_load_udp_missing_secret(self):
        """ _radius_config_load() returns None for udp without a secret """
        config_dic = {'RADIUS': {'server': '1.2.3.4'}}
        self.assertIsNone(self.esthandler._radius_config_load(config_dic))

    def test_087__radius_config_load_radsec(self):
        """ _radius_config_load() parses a radsec section (secret fixed, default port 2083, tls files) """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'proto': 'radsec', 'certfile_server': '/ca.pem', 'certfile': '/c.crt', 'keyfile': '/c.key', 'check_hostname': 'False', 'min_tls_version': '1.2'}}
        result = self.esthandler._radius_config_load(config_dic)
        self.assertEqual(result['proto'], 'radsec')
        self.assertEqual(result['secret'], 'radsec')
        self.assertEqual(result['port'], 2083)
        self.assertEqual(result['certfile_server'], '/ca.pem')
        self.assertEqual(result['certfile'], '/c.crt')
        self.assertEqual(result['keyfile'], '/c.key')
        self.assertFalse(result['check_hostname'])
        self.assertEqual(result['min_tls_version'], '1.2')

    def test_087a__radius_config_load_radsec_custom_secret(self):
        """ _radius_config_load() keeps an explicitly configured radsec secret """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'proto': 'radsec', 'secret': 'mysecret'}}
        result = self.esthandler._radius_config_load(config_dic)
        self.assertEqual(result['secret'], 'mysecret')

    def test_088__radius_config_load_no_section(self):
        """ _radius_config_load() returns None when no [RADIUS] section exists """
        self.assertIsNone(self.esthandler._radius_config_load({}))

    def test_088a__radius_config_load_empty_server(self):
        """ _radius_config_load() treats an empty server value as unset (section disabled) """
        config_dic = {'RADIUS': {'server': '', 'secret': 's3cr3t'}}
        self.assertIsNone(self.esthandler._radius_config_load(config_dic))

    def test_088b__radius_config_load_udp_empty_secret(self):
        """ _radius_config_load() treats an empty udp secret as missing (section disabled) """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'secret': ''}}
        self.assertIsNone(self.esthandler._radius_config_load(config_dic))

    def test_088c__radius_config_load_empty_values_fall_back_to_defaults(self):
        """ _radius_config_load() maps empty option values to their defaults (template ships blank lines) """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'proto': 'radsec', 'secret': '', 'port': '',
                                 'timeout': '', 'retries': '', 'nas_identifier': '', 'certfile': '',
                                 'keyfile': '', 'certfile_server': '', 'check_hostname': '',
                                 'min_tls_version': ''}}
        result = self.esthandler._radius_config_load(config_dic)
        self.assertEqual(result['proto'], 'radsec')
        self.assertEqual(result['secret'], 'radsec')
        self.assertEqual(result['port'], 2083)
        self.assertEqual(result['timeout'], 5)
        self.assertEqual(result['retries'], 1)
        self.assertEqual(result['nas_identifier'], 'est_proxy')
        self.assertIsNone(result['certfile'])
        self.assertIsNone(result['keyfile'])
        self.assertIsNone(result['certfile_server'])
        self.assertTrue(result['check_hostname'])
        self.assertEqual(result['min_tls_version'], '1.3')

    def test_088d__radius_config_load_empty_proto_defaults_to_udp(self):
        """ _radius_config_load() treats an empty proto value as udp """
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'proto': '', 'secret': 's3cr3t'}}
        result = self.esthandler._radius_config_load(config_dic)
        self.assertEqual(result['proto'], 'udp')
        self.assertEqual(result['port'], 1812)

    def test_088e__radius_config_load_disabled(self):
        """ _radius_config_load() returns None when enabled is False, regardless of the other options """
        config_dic = {'RADIUS': {'enabled': 'False', 'server': '1.2.3.4', 'secret': 's3cr3t'}}
        self.assertIsNone(self.esthandler._radius_config_load(config_dic))

    def test_088f__radius_config_load_enabled_missing_or_empty_counts_as_enabled(self):
        """ _radius_config_load() treats a missing or empty enabled value as enabled """
        config_dic = {'RADIUS': {'enabled': '', 'server': '1.2.3.4', 'secret': 's3cr3t'}}
        self.assertIsNotNone(self.esthandler._radius_config_load(config_dic))
        config_dic = {'RADIUS': {'server': '1.2.3.4', 'secret': 's3cr3t'}}
        self.assertIsNotNone(self.esthandler._radius_config_load(config_dic))

    def test_088g__radius_config_load_enabled_case_insensitive(self):
        """ _radius_config_load() parses the enabled switch case-insensitively """
        config_dic = {'RADIUS': {'enabled': 'true', 'server': '1.2.3.4', 'secret': 's3cr3t'}}
        self.assertIsNotNone(self.esthandler._radius_config_load(config_dic))
        config_dic = {'RADIUS': {'enabled': 'false', 'server': '1.2.3.4', 'secret': 's3cr3t'}}
        self.assertIsNone(self.esthandler._radius_config_load(config_dic))

    # --------------------------------------------------------------------- #
    # _check_csr_data() - CSR-injection / user-association security tests.
    # These port the attack battery from est-test_special.sh into unit tests:
    # the client is authenticated as 'test-client-01' (SAN test-client-01.example.com)
    # and every crafted CSR that deviates from that identity/profile must be rejected.
    # The basic-auth path is used (client_certificate = None), which is the
    # stricter path - the explicit checks must catch the attack on their own.
    # --------------------------------------------------------------------- #

    def _setup_csr_user(self):
        """ configure the handler as the legitimate test-client-01 identity.
            Uses the STRICT extension policy (subjectAltName only) so the injection
            tests below assert the hardened default-deny path. """
        from cryptography.x509.oid import ExtensionOID
        self.esthandler.client_certificate = None
        self.esthandler.csr_allowed_ext = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
        self.esthandler.user = {
            'common_name_regex': 'test-client-01',
            'dns_regex': r'test-client-01\.example\.com',
            'ip_regex': None,
        }

    # --- control ---------------------------------------------------------- #
    def test_089__check_csr_data_control_valid(self):
        """ faithful CSR (matching CN + SAN) is accepted """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com'])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    # --- category A: identity binding (already enforced) ------------------ #
    def test_090__check_csr_data_cn_server_impersonation(self):
        """ different CN (server impersonation) is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-server.example.com'], ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_091__check_csr_data_cn_arbitrary(self):
        """ arbitrary attacker CN is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['attacker.example.com'], ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_092__check_csr_data_san_add_server_dns(self):
        """ adding a second (server) DNS SAN is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com', 'DNS:test-server.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_093__check_csr_data_san_add_wildcard(self):
        """ adding a wildcard DNS SAN is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com', 'DNS:*.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_094__check_csr_data_san_add_ip(self):
        """ adding an IP SAN not matching ip_regex is rejected """
        self._setup_csr_user()
        # mirror the log scenario: the user IS restricted to a specific IP range,
        # so an out-of-range IP must be rejected by the ip_regex check.
        self.esthandler.user['ip_regex'] = r'127\.0\.0\.1'
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com', 'IP:10.0.0.1'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_095__check_csr_data_san_email_inject(self):
        """ a non-DNS/IP SAN (email) is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com', 'email:admin@example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    # --- category B: the fixes (previously issued / stripped) ------------- #
    def test_096__check_csr_data_multi_cn_rdn(self):
        """ a second CN RDN is rejected (was VULN: only the first CN was validated) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01', 'test-server.example.com'], ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_097__check_csr_data_subject_extra_attrs(self):
        """ extra subject RDNs (O/OU) are allowed on the basic-auth path (no client cert) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Example Inc', 'Devices')
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_097c__check_csr_data_subject_c_l_st_allowed(self):
        """ extra subject RDNs (C/L/ST) are allowed on the basic-auth path (no client cert) """
        from cryptography.x509.oid import NameOID
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_with_subject_attrs(
            'test-client-01', ['DNS:test-client-01.example.com'],
            [(NameOID.COUNTRY_NAME, 'AT'), (NameOID.LOCALITY_NAME, 'Vienna'), (NameOID.STATE_OR_PROVINCE_NAME, 'Vienna')])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_097d__check_csr_data_subject_disallowed_attr_type(self):
        """ a subject RDN type outside cn/o/ou/c/l/st (emailAddress) is rejected without a client cert """
        from cryptography.x509.oid import NameOID
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_with_subject_attrs(
            'test-client-01', ['DNS:test-client-01.example.com'],
            [(NameOID.EMAIL_ADDRESS, 'admin@example.com')])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_097e__check_csr_data_subject_mixed_allowed_and_disallowed(self):
        """ allowed O/OU do not smuggle a disallowed type (serialNumber) past the check """
        from cryptography.x509.oid import NameOID
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_with_subject_attrs(
            'test-client-01', ['DNS:test-client-01.example.com'],
            [(NameOID.ORGANIZATION_NAME, 'Example Inc'), (NameOID.SERIAL_NUMBER, '4711')])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_097a__check_csr_data_subject_extra_attrs_reenroll_match(self):
        """ extra subject RDNs are ALLOWED on reenroll when they match the presented client cert """
        self._setup_csr_user()
        self.esthandler.client_certificate = csr_fixtures.build_client_certificate(
            ['test-client-01'], ['DNS:test-client-01.example.com'], org='Example Inc', ou='Devices')
        csr = csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Example Inc', 'Devices')
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_097b__check_csr_data_subject_extra_attrs_reenroll_mismatch(self):
        """ extra subject RDNs are rejected on reenroll when they differ from the client cert """
        self._setup_csr_user()
        self.esthandler.client_certificate = csr_fixtures.build_client_certificate(
            ['test-client-01'], ['DNS:test-client-01.example.com'], org='Example Inc', ou='Devices')
        csr = csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Evil Corp', 'Unauthorized')
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_098__check_csr_data_eku_serverauth(self):
        """ an injected extendedKeyUsage extension is rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.extended_key_usage(['1.3.6.1.5.5.7.3.1']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_099__check_csr_data_keyusage_certsign(self):
        """ an injected keyUsage (keyCertSign) extension is rejected """
        from cryptography import x509
        self._setup_csr_user()
        key_usage = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                  crl_sign=True, encipher_only=False, decipher_only=False)
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(key_usage, True)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_100__check_csr_data_basic_constraints_ca(self):
        """ an injected basicConstraints CA:TRUE extension is rejected """
        from cryptography import x509
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(x509.BasicConstraints(ca=True, path_length=None), True)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_101__check_csr_data_policy_single_oid(self):
        """ an injected certificatePolicies extension is rejected (was VULN) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(['1.3.6.1.4.1.99999.7.7']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_102__check_csr_data_policy_anypolicy(self):
        """ an injected anyPolicy certificatePolicies extension is rejected (was VULN) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(['2.5.29.32.0']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_103__check_csr_data_policy_injection_multi(self):
        """ multiple injected policy OIDs are rejected (was VULN) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(
                ['1.3.6.1.4.1.99999.1.1', '1.3.6.1.4.1.99999.2.2', '2.5.29.32.0']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    # --- config-driven allowed_extensions ([CSRvalidation]) --------------- #
    def test_103a__check_csr_data_eku_allowed_by_config(self):
        """ with keyUsage/EKU/basicConstraints in the allowlist, an EKU CSR is accepted
            (mirrors the shipped default - the MS-WCCE template overrides it anyway) """
        from est_proxy.helper import csr_allowed_extensions
        self._setup_csr_user()
        self.esthandler.csr_allowed_ext = csr_allowed_extensions(
            self.esthandler.logger, 'keyUsage, extendedKeyUsage, basicConstraints')
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.extended_key_usage(['1.3.6.1.5.5.7.3.1']), False)])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_103b__check_csr_data_default_allowlist_rejects_policies(self):
        """ the default allowlist tolerates EKU but still REJECTS certificatePolicies
            (the CA copies it verbatim, so it is not in the default) """
        from est_proxy.helper import csr_allowed_extensions
        self._setup_csr_user()
        self.esthandler.csr_allowed_ext = csr_allowed_extensions(
            self.esthandler.logger, 'keyUsage, extendedKeyUsage, basicConstraints')
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(['1.3.6.1.4.1.99999.7.7']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_103c__check_csr_data_policies_allowed_when_explicitly_listed(self):
        """ an admin who explicitly lists certificatePolicies accepts the risk -> allowed
            (fully literal list; the code does not override the admin's choice) """
        from est_proxy.helper import csr_allowed_extensions
        self._setup_csr_user()
        self.esthandler.csr_allowed_ext = csr_allowed_extensions(
            self.esthandler.logger, 'certificatePolicies')
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(['1.3.6.1.4.1.99999.7.7']), False)])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_103d__check_csr_data_eku_still_rejected_if_not_listed(self):
        """ if the allowlist omits keyUsage, an EKU CSR is still rejected """
        from est_proxy.helper import csr_allowed_extensions
        self._setup_csr_user()
        self.esthandler.csr_allowed_ext = csr_allowed_extensions(self.esthandler.logger, 'basicConstraints')
        csr = csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.extended_key_usage(['1.3.6.1.5.5.7.3.1']), False)])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    # --- new gap cases (not covered by est-test_special.sh) --------------- #
    def test_104__check_csr_data_ms_cert_extensions_attr(self):
        """ extensions smuggled via the Microsoft szOID_CERT_EXTENSIONS attribute are rejected """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_ms_cert_extensions_attr('test-client-01')
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_105__check_csr_data_bad_signature(self):
        """ a CSR with an invalid self-signature is rejected (proof-of-possession) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr_bad_signature('test-client-01', ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_106__check_csr_data_empty_san_with_regex(self):
        """ a CSR omitting the DNS SAN while dns_regex is set is ACCEPTED:
            a value filter only constrains values that are present. The CSR carries
            no DNS SAN, so there is nothing to match against and nothing to abuse.
            (Regression from est-test: an admin who leaves the default '^.*' filter
            in place must still be able to enroll DNS-only or SAN-less CSRs.) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01'], sans=None)
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_106a__check_csr_data_wideopen_regex_no_ip(self):
        """ the est-test scenario: all filters '^.*', CSR has DNS but no IP SAN -> accepted """
        self.esthandler.client_certificate = None
        self.esthandler.user = {'common_name_regex': '^.*', 'dns_regex': '^.*', 'ip_regex': '^.*'}
        csr = csr_fixtures.build_csr(['test-server.example.com'],
                                     ['DNS:test-server.example.com', 'DNS:www.test-server.example.com'])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_106b__check_csr_data_present_ip_still_filtered(self):
        """ with ip_regex set, a present IP that does not match is still rejected """
        self._setup_csr_user()
        self.esthandler.user['ip_regex'] = r'127\.0\.0\.1'
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com', 'IP:10.0.0.1'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_107__check_csr_data_regex_suffix_bypass(self):
        """ a CN that merely has the allowed value as a prefix is rejected (fullmatch) """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr(['test-client-01.evil.com'], ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_108__check_csr_data_unloadable(self):
        """ garbage that is not a CSR is rejected """
        self._setup_csr_user()
        self.assertFalse(self.esthandler._check_csr_data(b'not-a-real-csr'))

    def test_109__check_csr_data_no_common_name(self):
        """ a CSR carrying no common name is rejected (est_handler.py 'No common name could be found') """
        self._setup_csr_user()
        csr = csr_fixtures.build_csr([], ['DNS:test-client-01.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))

    def test_110__check_csr_data_multiple_matching_ip(self):
        """ two IP SANs that both match ip_regex are accepted (multi-value SAN, all in range) """
        self._setup_csr_user()
        self.esthandler.user['ip_regex'] = r'10\.0\.0\.\d+'
        csr = csr_fixtures.build_csr(['test-client-01'],
                                     ['DNS:test-client-01.example.com', 'IP:10.0.0.1', 'IP:10.0.0.2'])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_111__check_csr_data_multiple_matching_dns(self):
        """ two DNS SANs that both match a specific (non-'^.*') dns_regex are accepted """
        self._setup_csr_user()
        self.esthandler.user['dns_regex'] = r'.+\.example\.com'
        csr = csr_fixtures.build_csr(['test-client-01'],
                                     ['DNS:a.example.com', 'DNS:b.example.com'])
        self.assertTrue(self.esthandler._check_csr_data(csr))

    def test_112__check_csr_data_reenroll_dns_mismatch(self):
        """ on reenroll (client cert presented) a CSR whose DNS passes the regex but differs
            from the presented certificate is rejected by the equal_content_list binding """
        self._setup_csr_user()
        self.esthandler.user['dns_regex'] = r'.+\.example\.com'
        self.esthandler.client_certificate = csr_fixtures.build_client_certificate(
            ['test-client-01'], ['DNS:test-client-01.example.com'])
        csr = csr_fixtures.build_csr(['test-client-01'], ['DNS:other.example.com'])
        self.assertFalse(self.esthandler._check_csr_data(csr))


if __name__ == '__main__':
    unittest.main()
