# -*- coding: utf-8 -*-
""" CA handler for Microsoft ICertPassage Remote Protocol (MS-ICPR) """
from __future__ import print_function
from typing import Optional, Tuple

# pylint: disable=E0401
from est_proxy.cahandlers.ms_icpr.request import Request
from est_proxy.cahandlers.ms_icpr.target import Target
from est_proxy.helper import config_load, convert_byte_to_string, convert_string_to_byte, build_pem_file


class CAhandler(object):
    """ MS-ICPR CA handler """

    def __init__(self, cfg_file=None, logger=None, template=None):
        self.cfg_file = cfg_file
        self.logger = logger
        self.host = None
        self.user = None
        self.password = None
        self.template = template
        self.target_domain = None
        self.domain_controller = None
        self.ca_name = None
        self.ca_bundle = None
        self.use_kerberos = False
        self.timeout = 5

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def _config_load(self):
        """ load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = config_load(self.logger, cfg_file=self.cfg_file)

        self.host = config_dic.get('CAhandler', 'host', fallback=None)
        self.user = config_dic.get('CAhandler', 'user', fallback=None)
        self.password = config_dic.get('CAhandler', 'password', fallback=None)
        self.target_domain = config_dic.get('CAhandler', 'target_domain', fallback=None)
        self.domain_controller = config_dic.get('CAhandler', 'domain_controller', fallback=None)
        self.ca_name = config_dic.get('CAhandler', 'ca_name', fallback=None)
        self.ca_bundle = config_dic.get('CAhandler', 'ca_bundle', fallback=None)
        self.use_kerberos = config_dic.getboolean('CAhandler', 'use_kerberos', fallback=False)

        self.logger.debug('CAhandler._config_load() ended')

    def _file_load(self, bundle: str) -> Optional[str]:
        """ load file """
        file_ = None
        try:
            with open(bundle, 'r', encoding='utf-8') as fso:
                file_ = fso.read()
        except Exception as err_:
            self.logger.error('CAhandler._file_load(): could not load %s. Error: %s', bundle, err_)
        return file_

    def request_create(self) -> Request:
        """ create request object """
        self.logger.debug('CAhandler.request_create()')

        target = Target(
            domain=self.target_domain,
            username=self.user,
            password=self.password,
            remote_name=self.host,
            dc_ip=self.domain_controller,
            timeout=self.timeout
        )
        request = Request(
            target=target,
            ca=self.ca_name,
            template=self.template,
            do_kerberos=self.use_kerberos
        )

        self.logger.debug('CAhandler.request_create() ended')
        return request

    def ca_certs_get(self) -> Optional[str]:
        """ get ca certificates """
        self.logger.debug('CAhandler.ca_certs_get()')

        ca_pem = None
        if self.ca_bundle:
            ca_pem = self._file_load(self.ca_bundle)

        self.logger.debug('CAhandler.ca_certs_get() ended with: %s', bool(ca_pem))
        return ca_pem

    def enroll(self, csr: str) -> Tuple[Optional[str], Optional[str], None]:
        """ enroll certificate via MS-ICPR """
        self.logger.debug('CAhandler.enroll(%s)', self.template)

        error = None
        cert_raw = None

        if not (self.host and self.user and self.password and self.template and self.ca_name):
            self.logger.error('Config incomplete')
            return ('Config incomplete', None, None)

        csr = build_pem_file(self.logger, None, csr, 64, True)

        try:
            request = self.request_create()
            cert_raw = convert_byte_to_string(
                request.get_cert(convert_string_to_byte(csr))
            )
            cert_raw = cert_raw.replace('\r\n', '\n')
        except Exception as err_:
            cert_raw = None
            error = f'{err_}'
            self.logger.error('CAhandler.enroll(): certificate request failed: %s', err_)

        self.logger.debug('CAhandler.enroll() ended')
        return (error, cert_raw, None)

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, None, None, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')
        return ('Method not implemented.', None, None, poll_identifier, False)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')
        return (500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.')

    def trigger(self, _payload: str) -> Tuple[str, None, None]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')
        return ('Method not implemented.', None, None)
