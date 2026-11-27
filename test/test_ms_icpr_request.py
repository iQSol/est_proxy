#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for the MS-ICPR request module """
# pylint: disable= C0415, E0401, R0904, W0201, W0212
import os
import sys
import unittest
from unittest.mock import patch, Mock

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, '.')
sys.path.insert(1, '..')
sys.path.insert(2, os.path.dirname(__file__))

import csr_fixtures

CA_DIR = os.path.join(os.path.dirname(__file__), 'ca')


def blob(data):
    """ emulate an NDR CERTTRANSBLOB as impacket returns it """
    return {'cb': len(data), 'pb': [bytes([byte]) for byte in data]}


def icpr_response(disposition, request_id=7, cert=b'', message=''):
    """ build a CertServerRequestResponse like dictionary """
    return {
        'pdwRequestId': request_id,
        'pdwDisposition': disposition,
        'pctbCert': blob(b''),
        'pctbEncodedCert': blob(cert),
        'pctbDispositionMessage': blob((message + '\x00').encode('utf-16le') if message else b''),
    }


class MsIcprRequestTestCases(unittest.TestCase):
    """ test class for the MS-ICPR request module """

    def setUp(self):
        """ setup unittest """
        from est_proxy.cahandlers.ms_icpr import request
        self.module = request
        with open(os.path.join(CA_DIR, 'sub-ca-cert.pem'), 'rb') as fso:
            self.cert_pem = fso.read()
        self.cert_der = x509.load_pem_x509_certificate(self.cert_pem).public_bytes(Encoding.DER)
        body = csr_fixtures.build_csr(['foo.example.com']).decode()
        self.csr_pem = f'-----BEGIN CERTIFICATE REQUEST-----\n{body}\n-----END CERTIFICATE REQUEST-----\n'.encode()
        self.target = Mock(timeout=5)

    def _request(self, response=None):
        with patch('est_proxy.cahandlers.ms_icpr.request.get_dce_rpc') as mock_dce:
            mock_dce.return_value.request.return_value = response
            request = self.module.Request(target=self.target, ca='example-CA', template='EST_Webserver', do_kerberos=True)
        self.assertEqual(r'\pipe\cert', mock_dce.call_args[0][1])
        self.assertTrue(mock_dce.call_args[1]['do_kerberos'])
        self.assertEqual(5, mock_dce.call_args[1]['timeout'])
        return request

    def test_001_get_cert(self):
        """ disposition 3 returns the issued certificate in pem format """
        request = self._request(icpr_response(3, cert=self.cert_der))
        self.assertEqual(x509.load_der_x509_certificate(self.cert_der).public_bytes(Encoding.PEM), request.get_cert(self.csr_pem))

        rpc_request = request.dce.request.call_args[0][0]
        self.assertEqual(0, rpc_request['dwFlags'])
        self.assertEqual('example-CA\x00', rpc_request['pwszAuthority'])
        self.assertEqual('CertificateTemplate:EST_Webserver\x00'.encode('utf-16le'), rpc_request['pctbAttribs']['pb'])
        self.assertEqual(self.module.csr_pem_to_der(self.csr_pem), rpc_request['pctbRequest']['pb'])

    def test_002_get_cert(self):
        """ disposition 5 raises a pending error """
        request = self._request(icpr_response(5, request_id=42))
        with self.assertRaisesRegex(RuntimeError, r'^Certificate request is pending approval \(request id 42\)$'):
            request.get_cert(self.csr_pem)

    def test_003_get_cert(self):
        """ a denied request raises an error with the translated code and the CA message """
        request = self._request(icpr_response(0x80094012, request_id=9, message='The template is not allowed.'))
        with self.assertRaises(RuntimeError) as err:
            request.get_cert(self.csr_pem)
        self.assertIn('Certificate request denied (request id 9): code: 0x80094012', str(err.exception))
        self.assertIn('CERTSRV_E_TEMPLATE_DENIED', str(err.exception))
        self.assertTrue(str(err.exception).endswith(' - The template is not allowed.'))

    def test_004_get_cert(self):
        """ an unknown error code without a message """
        request = self._request(icpr_response(0x1234))
        with self.assertRaisesRegex(RuntimeError, r'unknown error code: 0x1234$'):
            request.get_cert(self.csr_pem)

    def test_005_get_cert(self):
        """ an issued disposition without a certificate raises an error """
        request = self._request(icpr_response(3))
        with self.assertRaisesRegex(RuntimeError, r'^CA returned no certificate \(request id 7\)$'):
            request.get_cert(self.csr_pem)

    def test_006_get_cert(self):
        """ no rpc connection raises a connection error """
        with patch('est_proxy.cahandlers.ms_icpr.request.get_dce_rpc', return_value=None):
            request = self.module.Request(target=self.target, ca='example-CA', template='EST_Webserver')
        with self.assertRaises(ConnectionError):
            request.get_cert(self.csr_pem)

    def test_007_disposition_message_decode(self):
        """ disposition_message_decode() edge cases """
        self.assertEqual('', self.module.disposition_message_decode(b''))
        self.assertEqual('', self.module.disposition_message_decode(b'\x00'))
        self.assertEqual('denied', self.module.disposition_message_decode('denied\x00\r\n'.encode('utf-16le')))

    def test_008_blob_bytes(self):
        """ blob_bytes() handles empty pointers """
        self.assertEqual(b'', self.module.blob_bytes({'pb': None}))
        self.assertEqual(b'', self.module.blob_bytes({'pb': []}))
        self.assertEqual(b'ab', self.module.blob_bytes({'pb': [b'a', b'b']}))


if __name__ == '__main__':
    unittest.main()
