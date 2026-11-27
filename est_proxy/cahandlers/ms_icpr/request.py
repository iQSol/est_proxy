""" MS-ICPR certificate request """
# pylint: disable=E0401, R0913
import logging

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from impacket.dcerpc.v5.icpr import (
    CERTTRANSBLOB,
    MSRPC_UUID_ICPR,
    CertServerRequest,
    translate_error_code,
)
from impacket.dcerpc.v5.nrpc import checkNullString

from est_proxy.cahandlers.ms_icpr.rpc import get_dce_rpc
from est_proxy.cahandlers.ms_icpr.target import Target

CR_DISP_ISSUED = 3
CR_DISP_UNDER_SUBMISSION = 5


def csr_pem_to_der(csr: bytes) -> bytes:
    """ convert pem to der """
    return x509.load_pem_x509_csr(csr).public_bytes(Encoding.DER)


def der_to_pem(certificate: bytes) -> bytes:
    """ convert der to pem """
    return x509.load_der_x509_certificate(certificate).public_bytes(Encoding.PEM)


def blob_bytes(blob) -> bytes:
    """ return the content of a CERTTRANSBLOB as bytes """
    data = blob['pb']
    if not data:
        return b''
    return b''.join(data)


def blob_create(data: bytes) -> CERTTRANSBLOB:
    """ create a CERTTRANSBLOB """
    blob = CERTTRANSBLOB()
    blob['cb'] = len(data)
    blob['pb'] = data
    return blob


def disposition_message_decode(raw: bytes) -> str:
    """ decode the UTF-16LE disposition message of the CA """
    if not raw:
        return ''
    try:
        return raw.decode('utf-16le').split('\x00', 1)[0].strip()
    except UnicodeDecodeError:
        return ''


class Request:
    """ MS-ICPR certificate request """
    # pylint: disable=c0103
    def __init__(
        self,
        target: Target = None,
        ca: str = None,
        template: str = None,
        debug=False,
        do_kerberos=False,
    ):
        self.target = target
        self.ca = ca
        self.template = template
        self.request_id = 0
        self.dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            r"\pipe\cert",
            self.target,
            timeout=self.target.timeout,
            verbose=debug,
            do_kerberos=do_kerberos
        )

    def _attributes_get(self) -> bytes:
        """ build the request attribute blob """
        return checkNullString(f'CertificateTemplate:{self.template}').encode('utf-16le')

    def get_cert(self, csr: bytes) -> bytes:
        """ submit a pem csr and return the issued certificate in pem format """
        if self.dce is None:
            raise ConnectionError('Could not connect to the CA RPC endpoint')

        request = CertServerRequest()
        request['dwFlags'] = 0
        request['pwszAuthority'] = checkNullString(self.ca)
        request['pdwRequestId'] = self.request_id
        request['pctbAttribs'] = blob_create(self._attributes_get())
        request['pctbRequest'] = blob_create(csr_pem_to_der(csr))

        logging.info('Requesting certificate')
        response = self.dce.request(request)

        disposition = response['pdwDisposition']
        request_id = response['pdwRequestId']
        message = disposition_message_decode(blob_bytes(response['pctbDispositionMessage']))
        logging.info('Request ID is %d', request_id)

        if disposition == CR_DISP_ISSUED:
            cert_der = blob_bytes(response['pctbEncodedCert'])
            if not cert_der:
                raise RuntimeError(f'CA returned no certificate (request id {request_id})')
            return der_to_pem(cert_der)

        if disposition == CR_DISP_UNDER_SUBMISSION:
            raise RuntimeError(f'Certificate request is pending approval (request id {request_id})')

        error = translate_error_code(disposition)
        if message:
            error = f'{error} - {message}'
        raise RuntimeError(f'Certificate request denied (request id {request_id}): {error}')
