#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for helper """
# pylint: disable=C0302, C0415, E0401, R0902, R0904, R0913, R0914, R0915, W0212
import unittest
import configparser
import os
import sys
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')
sys.path.insert(2, os.path.dirname(__file__))

import csr_fixtures

class HelperTestCases(unittest.TestCase):
    """ test class for helper """
    def setUp(self):
        """ setup """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        from est_proxy.helper import config_load, hssrv_options_get, connection_log, b64decode_pad, b64_url_recode, build_pem_file, ca_handler_get, convert_byte_to_string, convert_string_to_byte, uts_to_date_utc, logger_setup, san_check, get_cn_and_san, check_for_other_subject_attributes, check_for_other_extensions, check_for_other_attributes, csr_allowed_extensions, equal_subjects
        self.csr_allowed_extensions = csr_allowed_extensions
        self.san_check = san_check
        self.get_cn_and_san = get_cn_and_san
        self.check_for_other_subject_attributes = check_for_other_subject_attributes
        self.check_for_other_extensions = check_for_other_extensions
        self.check_for_other_attributes = check_for_other_attributes
        self.equal_subjects = equal_subjects
        self.b64_url_recode = b64_url_recode
        self.b64decode_pad = b64decode_pad
        self.build_pem_file = build_pem_file
        self.ca_handler_get = ca_handler_get
        self.config_load = config_load
        self.connection_log = connection_log
        self.convert_byte_to_string = convert_byte_to_string
        self.convert_string_to_byte = convert_string_to_byte
        self.logger_setup = logger_setup
        self.logger = logging.getLogger('test_est')
        self.hssrv_options_get = hssrv_options_get
        self.uts_to_date_utc = uts_to_date_utc

    def tearDown(self):
        """ teardown test environment """
        # Clean up run after every test method.

    def test_001_allways_ok(self):
        """ a test that never failes """
        self.assertEqual('foo', 'foo')

    def test_002_hssrv_options_get(self):
        """ test handshake options empty config dic and wrong task"""
        config_dic = {}
        task = 'wrong task'
        self.assertEqual({}, self.hssrv_options_get(self.logger, config_dic))

    def test_003_hssrv_options_get(self):
        """ test handshake options empty config dic Daemon task """
        config_dic = {}
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): Daemon specified but not configured in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_004_hssrv_options_get(self):
        """ test handshake options empty config dic Daemon task """
        config_dic = {'Daemon': {'foo': 'bar'}}
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): incomplete Daemon configuration in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_005_hssrv_options_get(self):
        """ test handshake options empty config dic Daemon task """
        config_dic = {'Daemon': {'cert_file': 'cert_file', 'foo': 'bar'}}
        expected_log = 'ERROR:test_est:Helper.hssrv_options_get(): incomplete Daemon configuration in config file'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual({}, self.hssrv_options_get(self.logger, config_dic))
        self.assertIn(expected_log, lcm.output)

    def test_006_hssrv_options_get(self):
        """ test handshake options empty config dic Daemon task """
        config_dic = {'Daemon': {'cert_file': 'cert_file', 'key_file': 'key_file'}}
        foo_ = {'sni': None, 'privateKey': 'key_file', 'certChain': 'cert_file', 'alpn': [bytearray(b'http/1.1')]}
        self.assertTrue(foo_.items() <= self.hssrv_options_get(self.logger, config_dic).items())

    def test_007_hssrv_options_get(self):
        """ test handshake options enforce a TLS 1.2 minimum version (RFC 7030 section 3.3) """
        config_dic = {'Daemon': {'cert_file': 'cert_file', 'key_file': 'key_file'}}
        option_dic = self.hssrv_options_get(self.logger, config_dic)
        self.assertEqual((3, 3), option_dic['settings'].minVersion)

    def test_011_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, 'fafafa'))

    def test_012_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, 'fafaf'))

    def test_013_helper_b64_url_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, 'fafafafa'))

    def test_014_helper_b64_url_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, 'fafa-f'))

    def test_015_helper_b64_url_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, 'fafa_f'))

    def test_016_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, b'fafafaf'))

    def test_017_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, b'fafafa'))

    def test_018_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, b'fafaf'))

    def test_019_helper_b64_url_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, b'fafafafa'))

    def test_020_helper_b64_url_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, b'fafa-f'))

    def test_021_helper_b64_url_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, b'fafa_f'))

    def test_022_helper_build_pem_file(self):
        """ test build_pem_file without exsting content """
        existing = None
        cert = 'cert'
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_023_helper_build_pem_file(self):
        """ test build_pem_file with exsting content """
        existing = 'existing'
        cert = 'cert'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_024_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_025_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    def test_026_helper_build_pem_file(self):
        """ test build_pem_file for CSR """
        existing = None
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=='
        result = """-----BEGIN CERTIFICATE REQUEST-----
MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CT
ZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDg
WlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4
FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZb
eI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY
9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3
BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJh
ci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7
n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAt
iUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYu
tUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9I
NJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQs
KxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A==
-----END CERTIFICATE REQUEST-----
"""
        self.assertEqual(result, self.build_pem_file(self.logger, existing, csr, False, True))

    def test_027_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = 'existing'
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    def test_027_helper_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo'
        self.assertEqual('foo', self.ca_handler_get(self.logger, file_name))

    def test_028_helper_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo.py'
        self.assertEqual('foo', self.ca_handler_get(self.logger, file_name))

    def test_029_helper_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo/foo.py'
        self.assertEqual('foo.foo', self.ca_handler_get(self.logger, file_name))

    def test_030_helper_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo\\foo.py'
        self.assertEqual('foo.foo', self.ca_handler_get(self.logger, file_name))

    def test_032_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_033_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_034_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string('foobar'))

    def test_035_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string(b'foobar'))

    def test_036_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = 'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_037_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_038_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_039_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = ''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_040_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = None
        self.assertFalse(self.convert_string_to_byte(value))

    def test_048_helper_uts_to_date_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_049_helper_uts_to_date_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_050_helper_b64decode_pad(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_051_helper_b64decode_pad(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_052_helper_b64decode_pad(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.b64decode_pad(self.logger, 'b'))

    def test_060_logger_setup(self):
        """ stupid logger setup """
        debug = False
        cfg_file =None
        self.assertTrue(self.logger_setup(debug, cfg_file))

    def test_061_logger_setup(self):
        """ stupid logger setup """
        debug = True
        cfg_file =None
        self.assertTrue(self.logger_setup(debug, cfg_file))

    def test_062_logger_setup(self):
        """ stupid logger setup """
        debug = False
        cfg_file = 'cfg_file'
        self.assertTrue(self.logger_setup(debug, cfg_file))

    @patch('tlslite.constants.CipherSuite.ietfNames')
    def test_063__connection_log(self, mockcs):
        """ stupid connection logger """
        seconds = 10
        mockcs.return_value = 'foo'
        msession = Mock()
        msession.cipherSuite = Mock(return_value='cipherSuite')
        connection = Mock()
        connection.getpeername = Mock(return_value='getpeername')
        connection.getVersionName = Mock(return_value='getVersionName')
        connection.getCipherName = Mock(return_value='getCipherName')
        connection.getCipherImplementation = Mock(return_value='getCipherImplementation')
        connection.version = (2, 1)
        connection.dhGroupSize = 'dhGroupSize'
        connection.next_proto = 'next_proto'
        connection.encryptThenMAC = 'encryptThenMAC'
        connection.extendedMasterSecret = 'extendedMasterSecret'
        connection.session = Mock(return_value=msession)
        with self.assertLogs('test_est', level='DEBUG') as lcm:
            self.connection_log(self.logger, connection, seconds)
        self.assertIn('DEBUG:test_est:Remote end: getpeername', lcm.output)
        self.assertIn('DEBUG:test_est: Handshake time: 10.000 seconds', lcm.output)
        self.assertIn('DEBUG:test_est: Version: getVersionName', lcm.output)
        self.assertIn('DEBUG:test_est: Cipher: getCipherName getCipherImplementation', lcm.output)
        self.assertIn('DEBUG:test_est: DH group size: dhGroupSize bits', lcm.output)
        self.assertIn('DEBUG:test_est: Next-Protocol Negotiated: next_proto', lcm.output)
        self.assertIn('DEBUG:test_est: Encrypt-then-MAC: encryptThenMAC', lcm.output)
        self.assertIn('DEBUG:test_est: Extended Master Secret: extendedMasterSecret', lcm.output)

    # --------------------------------------------------------------------- #
    # CSR validation helpers (security hardening)
    # --------------------------------------------------------------------- #

    @staticmethod
    def _load_csr(body):
        """ load a CSR from a header-stripped base64 body (as the handler does) """
        from cryptography import x509
        return x509.load_pem_x509_csr(b'-----BEGIN CERTIFICATE REQUEST-----\n' + body + b'-----END CERTIFICATE REQUEST-----\n')

    def test_064_san_check_no_pattern(self):
        """ san_check() no pattern configured -> always True """
        self.assertTrue(self.san_check(self.logger, None, ['anything']))

    def test_065_san_check_exact_match(self):
        """ san_check() value matching the whole pattern -> True """
        self.assertTrue(self.san_check(self.logger, 'test-client-01', ['test-client-01']))

    def test_066_san_check_suffix_bypass_rejected(self):
        """ san_check() fullmatch: a suffix must NOT bypass the pattern """
        self.assertFalse(self.san_check(self.logger, 'test-client-01', ['test-client-01.evil.com']))

    def test_067_san_check_prefix_bypass_rejected(self):
        """ san_check() fullmatch: a prefix must NOT bypass the pattern """
        self.assertFalse(self.san_check(self.logger, r'client\.example\.com', ['client.example.com.attacker.net']))

    def test_068_san_check_empty_list_with_pattern(self):
        """ san_check() empty list while a pattern is configured -> allowed
            (a value filter only constrains values that are present; a CSR carrying
            no SAN of this type has nothing to abuse. '^.*' therefore means
            "any value, including none" - see est-test regression) """
        self.assertTrue(self.san_check(self.logger, '^10\\..*', []))
        self.assertTrue(self.san_check(self.logger, '^.*', []))

    def test_068a_san_check_present_value_still_enforced(self):
        """ san_check() a present value that does not match is still rejected """
        self.assertFalse(self.san_check(self.logger, '^10\\..*', ['192.168.0.1']))

    def test_069_san_check_wildcard_pattern_matches(self):
        """ san_check() a pattern that spans the whole value still matches """
        self.assertTrue(self.san_check(self.logger, r'.*\.example\.com', ['a.example.com', 'b.example.com']))

    def test_069a_csr_allowed_extensions_always_includes_san(self):
        """ csr_allowed_extensions() always includes subjectAltName, even for '' """
        from cryptography.x509.oid import ExtensionOID
        result = self.csr_allowed_extensions(self.logger, '')
        self.assertEqual({ExtensionOID.SUBJECT_ALTERNATIVE_NAME}, result)

    def test_069b_csr_allowed_extensions_resolves_names(self):
        """ csr_allowed_extensions() maps friendly names (case-insensitive) to OIDs """
        from cryptography.x509.oid import ExtensionOID
        result = self.csr_allowed_extensions(self.logger, ' keyUsage, EXTENDEDKEYUSAGE ,basicConstraints')
        self.assertEqual(
            {ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.KEY_USAGE,
             ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.BASIC_CONSTRAINTS},
            result)

    def test_069c_csr_allowed_extensions_accepts_dotted_oid(self):
        """ csr_allowed_extensions() accepts a raw dotted OID """
        from cryptography.x509 import ObjectIdentifier
        result = self.csr_allowed_extensions(self.logger, '2.5.29.32')
        self.assertIn(ObjectIdentifier('2.5.29.32'), result)

    def test_069d_csr_allowed_extensions_skips_unknown(self):
        """ csr_allowed_extensions() logs and skips an unknown name """
        from cryptography.x509.oid import ExtensionOID
        with self.assertLogs('test_est', level='ERROR') as lcm:
            result = self.csr_allowed_extensions(self.logger, 'keyUsage, bogusExtension')
        self.assertEqual({ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.KEY_USAGE}, result)
        self.assertTrue(any('bogusExtension' in line for line in lcm.output))

    def test_069d1_csr_allowed_extensions_skips_malformed_oid(self):
        """ csr_allowed_extensions() logs and skips a digit-leading entry that is not a valid dotted OID """
        from cryptography.x509.oid import ExtensionOID
        with self.assertLogs('test_est', level='ERROR') as lcm:
            result = self.csr_allowed_extensions(self.logger, 'keyUsage, 2.5.29.')
        self.assertEqual({ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.KEY_USAGE}, result)
        self.assertTrue(any('2.5.29.' in line for line in lcm.output))

    def test_069e_csr_allowed_extensions_can_include_policies(self):
        """ csr_allowed_extensions() honors an explicit certificatePolicies (fully literal) """
        from cryptography.x509.oid import ExtensionOID
        result = self.csr_allowed_extensions(self.logger, 'certificatePolicies')
        self.assertIn(ExtensionOID.CERTIFICATE_POLICIES, result)

    def test_070_get_cn_and_san_single_cn(self):
        """ get_cn_and_san() returns the single common name """
        csr = self._load_csr(csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com']))
        result = self.get_cn_and_san(csr)
        self.assertEqual(['test-client-01'], result['cn'])
        self.assertEqual(['test-client-01.example.com'], result['dns'])

    def test_071_get_cn_and_san_multi_cn(self):
        """ get_cn_and_san() returns ALL common names (not just the first) """
        csr = self._load_csr(csr_fixtures.build_csr(['test-client-01', 'test-server.example.com'], ['DNS:test-client-01.example.com']))
        self.assertEqual(['test-client-01', 'test-server.example.com'], self.get_cn_and_san(csr)['cn'])

    def test_072_check_for_other_subject_attributes_clean(self):
        """ check_for_other_subject_attributes() CN-only subject -> empty """
        csr = self._load_csr(csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com']))
        self.assertEqual([], self.check_for_other_subject_attributes(csr))

    def test_073_check_for_other_subject_attributes_org(self):
        """ check_for_other_subject_attributes() O/OU present -> non-empty """
        csr = self._load_csr(csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Evil Corp', 'Unauthorized'))
        self.assertTrue(self.check_for_other_subject_attributes(csr))

    def test_074_check_for_other_extensions_san_only(self):
        """ check_for_other_extensions() subjectAltName only -> empty """
        csr = self._load_csr(csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com']))
        self.assertEqual([], self.check_for_other_extensions(csr))

    def test_075_check_for_other_extensions_policies(self):
        """ check_for_other_extensions() certificatePolicies present -> non-empty """
        csr = self._load_csr(csr_fixtures.build_csr(
            ['test-client-01'], ['DNS:test-client-01.example.com'],
            extra_extensions=[(csr_fixtures.certificate_policies(['1.3.6.1.4.1.99999.7.7']), False)]))
        self.assertTrue(self.check_for_other_extensions(csr))

    def test_076_check_for_other_attributes_extension_request(self):
        """ check_for_other_attributes() a normal CSR (extensionRequest) -> empty """
        csr = self._load_csr(csr_fixtures.build_csr(['test-client-01'], ['DNS:test-client-01.example.com']))
        self.assertEqual([], self.check_for_other_attributes(csr))

    def test_077_check_for_other_attributes_ms_cert_extensions(self):
        """ check_for_other_attributes() Microsoft szOID_CERT_EXTENSIONS attr -> non-empty (fails closed) """
        csr = self._load_csr(csr_fixtures.build_csr_ms_cert_extensions_attr('test-client-01'))
        self.assertTrue(self.check_for_other_attributes(csr))

    def test_078_equal_subjects_match(self):
        """ equal_subjects() identical subjects (any order) -> True """
        csr = self._load_csr(csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Example Inc', 'Devices'))
        cert = csr_fixtures.build_client_certificate(['test-client-01'], ['DNS:test-client-01.example.com'], org='Example Inc', ou='Devices')
        self.assertTrue(self.equal_subjects(self.logger, cert.subject, csr.subject))

    def test_079_equal_subjects_mismatch(self):
        """ equal_subjects() differing subjects -> False """
        csr = self._load_csr(csr_fixtures.build_csr_with_org('test-client-01', ['DNS:test-client-01.example.com'], 'Evil Corp', 'Unauthorized'))
        cert = csr_fixtures.build_client_certificate(['test-client-01'], ['DNS:test-client-01.example.com'], org='Example Inc', ou='Devices')
        self.assertFalse(self.equal_subjects(self.logger, cert.subject, csr.subject))


if __name__ == '__main__':
    unittest.main()
