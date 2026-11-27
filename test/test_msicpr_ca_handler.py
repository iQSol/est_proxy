#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for the MS-ICPR CA handler """
# pylint: disable= C0415, E0401, R0904, W0201, W0212
import configparser
import os
import sys
import unittest
from unittest.mock import patch, mock_open

sys.path.insert(0, '.')
sys.path.insert(1, '..')
sys.path.insert(2, os.path.dirname(__file__))

import csr_fixtures


def config_build(options):
    """ build a ConfigParser with a CAhandler section """
    config = configparser.ConfigParser()
    config['CAhandler'] = options
    return config


class MsicprCAhandlerTestCases(unittest.TestCase):
    """ test class for the MS-ICPR CA handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_est')
        from est_proxy.cahandlers.msicpr_ca_handler import CAhandler
        self.cahandler = CAhandler(None, self.logger, 'template')

    def _config_complete(self):
        self.cahandler.host = 'ca.example.com'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.ca_name = 'example-CA'

    @patch('est_proxy.cahandlers.msicpr_ca_handler.config_load')
    def test_001_config_load(self, mock_load):
        """ _config_load() maps all keys """
        mock_load.return_value = config_build({
            'host': 'ca.example.com', 'user': 'user', 'password': 'password',
            'target_domain': 'example.com', 'domain_controller': '10.0.0.1',
            'ca_name': 'example-CA', 'ca_bundle': '/tmp/bundle.pem', 'use_kerberos': 'True'})
        self.cahandler._config_load()
        self.assertEqual('ca.example.com', self.cahandler.host)
        self.assertEqual('user', self.cahandler.user)
        self.assertEqual('password', self.cahandler.password)
        self.assertEqual('example.com', self.cahandler.target_domain)
        self.assertEqual('10.0.0.1', self.cahandler.domain_controller)
        self.assertEqual('example-CA', self.cahandler.ca_name)
        self.assertEqual('/tmp/bundle.pem', self.cahandler.ca_bundle)
        self.assertTrue(self.cahandler.use_kerberos)
        self.assertEqual('template', self.cahandler.template)

    @patch('est_proxy.cahandlers.msicpr_ca_handler.config_load')
    def test_002_config_load(self, mock_load):
        """ _config_load() defaults """
        mock_load.return_value = config_build({'host': 'ca.example.com'})
        self.cahandler._config_load()
        self.assertIsNone(self.cahandler.user)
        self.assertIsNone(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    def test_003_enroll(self):
        """ enroll() reports incomplete config for each missing key """
        for key in ('host', 'user', 'password', 'ca_name', 'template'):
            self._config_complete()
            self.cahandler.template = 'template'
            setattr(self.cahandler, key, None)
            with self.assertLogs('test_est', level='INFO') as lcm:
                self.assertEqual(('Config incomplete', None, None), self.cahandler.enroll('csr'))
            self.assertIn('ERROR:test_est:Config incomplete', lcm.output)

    @patch('est_proxy.cahandlers.msicpr_ca_handler.CAhandler.request_create')
    def test_004_enroll(self, mock_request):
        """ enroll() returns the certificate with lf line ends """
        self._config_complete()
        mock_request.return_value.get_cert.return_value = b'-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n'
        csr = csr_fixtures.build_csr(['foo.example.com']).decode()
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', None), self.cahandler.enroll(csr))
        submitted = mock_request.return_value.get_cert.call_args[0][0]
        self.assertTrue(submitted.startswith(b'-----BEGIN CERTIFICATE REQUEST-----\n'))

    @patch('est_proxy.cahandlers.msicpr_ca_handler.CAhandler.request_create')
    def test_005_enroll(self, mock_request):
        """ enroll() returns the error text of a failed request """
        self._config_complete()
        mock_request.return_value.get_cert.side_effect = RuntimeError('Certificate request denied (request id 7): denied')
        csr = csr_fixtures.build_csr(['foo.example.com']).decode()
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertEqual(('Certificate request denied (request id 7): denied', None, None), self.cahandler.enroll(csr))
        self.assertIn('ERROR:test_est:CAhandler.enroll(): certificate request failed: Certificate request denied (request id 7): denied', lcm.output)

    @patch('est_proxy.cahandlers.msicpr_ca_handler.CAhandler.request_create')
    def test_006_enroll(self, mock_request):
        """ enroll() returns an error when the RPC connection fails """
        self._config_complete()
        mock_request.side_effect = ConnectionError('no route')
        csr = csr_fixtures.build_csr(['foo.example.com']).decode()
        with self.assertLogs('test_est', level='INFO'):
            self.assertEqual(('no route', None, None), self.cahandler.enroll(csr))

    @patch('est_proxy.cahandlers.msicpr_ca_handler.Request')
    @patch('est_proxy.cahandlers.msicpr_ca_handler.Target')
    def test_007_request_create(self, mock_target, mock_request):
        """ request_create() passes the configuration """
        self._config_complete()
        self.cahandler.target_domain = 'example.com'
        self.cahandler.domain_controller = '10.0.0.1'
        self.cahandler.use_kerberos = True
        self.assertEqual(mock_request.return_value, self.cahandler.request_create())
        mock_target.assert_called_once_with(domain='example.com', username='user', password='password', remote_name='ca.example.com', dc_ip='10.0.0.1', timeout=5)
        mock_request.assert_called_once_with(target=mock_target.return_value, ca='example-CA', template='template', do_kerberos=True)

    def test_008_ca_certs_get(self):
        """ ca_certs_get() loads the bundle file """
        self.cahandler.ca_bundle = 'bundle.pem'
        with patch('builtins.open', mock_open(read_data='bundle')):
            self.assertEqual('bundle', self.cahandler.ca_certs_get())

    def test_009_ca_certs_get(self):
        """ ca_certs_get() with a missing bundle file """
        self.cahandler.ca_bundle = '/nonexistent/bundle.pem'
        with self.assertLogs('test_est', level='INFO') as lcm:
            self.assertIsNone(self.cahandler.ca_certs_get())
        self.assertTrue(any('could not load /nonexistent/bundle.pem' in line for line in lcm.output))

    def test_010_ca_certs_get(self):
        """ ca_certs_get() without bundle """
        self.assertIsNone(self.cahandler.ca_certs_get())

    def test_011_stubs(self):
        """ poll(), revoke() and trigger() are not implemented """
        self.assertEqual(('Method not implemented.', None, None, 'poll_id', False), self.cahandler.poll('name', 'poll_id', 'csr'))
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))


if __name__ == '__main__':
    unittest.main()
