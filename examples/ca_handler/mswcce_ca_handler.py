# -*- coding: utf-8 -*-
""" CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) """
from __future__ import print_function
from typing import Tuple

# pylint: disable=e0401, e0611
from examples.ca_handler.ms_wcce.target import Target
from examples.ca_handler.ms_wcce.request import Request

# pylint: disable=E0401
from est_proxy.helper import config_load, convert_byte_to_string, convert_string_to_byte, build_pem_file


class CAhandler(object):
    """MS-WCCE CA handler"""

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
        self.ca_bundle = False
        self.use_kerberos = False
        self.timeout = 5

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = config_load(self.logger, cfg_file=self.cfg_file)

        self.host = config_dic.get('CAhandler', 'host', fallback=None)
        self.user = config_dic.get('CAhandler', 'user', fallback=None)
        self.password = config_dic.get('CAhandler', 'password', fallback=None)
        self.target_domain = config_dic.get('CAhandler', 'target_domain', fallback=None)
        self.ca_name = config_dic.get('CAhandler', 'ca_name', fallback=None)
        self.ca_bundle = config_dic.get('CAhandler', 'ca_bundle', fallback=None)
        self.use_kerberos = config_dic.getboolean('CAhandler', 'use_kerberos', fallback=False)

        self.logger.debug('CAhandler._config_load() ended')

    def _file_load(self, bundle: str) -> str:
        """ load file """
        file_ = None
        try:
            with open(bundle, 'r', encoding='utf-8') as fso:
                file_ = fso.read()
        except Exception as err_:
            self.logger.error('CAhandler._file_load(): could not load %s. Error: %s', bundle, err_)
        return file_

    def request_create(self) -> Request:
        """create request object """
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
    def ca_certs_get(self):
        """ get ca certificates """
        self.logger.debug('CAhandler.ca_certs_get()')

        ca_pem = None

        ca_pem = self._file_load(self.ca_bundle)

        return ca_pem

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate via MS-WCCE"""
        self.logger.debug("CAhandler.enroll(%s)", self.template)

        error = None
        cert_raw = None

        if not (self.host and self.user and self.password and self.template):
            self.logger.error("Config incomplete")
            return ("Config incomplete", None, None, None)

        self.logger.debug("ε=ε=┌( >_<)┘ EST over mswcce...")

        # create request
        request = self.request_create()

        # recode csr
        csr = build_pem_file(self.logger, None, csr, 64, True)

        try:
            # request certificate
            cert_raw = convert_byte_to_string(
                request.get_cert(convert_string_to_byte(csr))
            )
            # replace crlf with lf
            cert_raw = cert_raw.replace("\r\n", "\n")
        except Exception as err_:
            cert_raw = None
            self.logger.error("ca_server.get_cert() failed with error: %s", err_)

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_raw, None)

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.tsg_id_lookup()")
        # get serial from pem file and convert to formated hex

        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = "Revocation is not supported."

        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
