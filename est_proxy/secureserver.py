# -*- coding: utf-8 -*-
""" HTTPServer based secure server """
import socket
import struct
from socketserver import ThreadingMixIn
from http.server import HTTPServer
from tlslite.api import TLSSocketServerMixIn, parsePEMKey, X509CertChain, TLSLocalAlert, TLSRemoteAlert, AlertDescription
from tlslite.utils.compat import b2a_hex, a2b_hex, time_stamp
# pylint: disable=E0401
from est_proxy.helper import config_load, logger_setup, hssrv_options_get, printgoodconnection

class SecureServer(ThreadingMixIn, TLSSocketServerMixIn, HTTPServer):
    """ Secure server """
    logger = None
    config_dic = {}

    def __init__(self, *args, **kwargs):
        self._config_load()
        # Instantiate the superclass
        super().__init__(*args, **kwargs)

    def _config_load(self):
        """ load config from file """

        config_dic = config_load()
        debug = config_dic.getboolean('DEFAULT', 'debug', fallback=False)
        self.logger = logger_setup(debug)

        if 'ClientAuth' in config_dic:
            self.config_dic['ClientAuth'] = {}
            self.config_dic['ClientAuth']['address'] = config_dic.get('ClientAuth', 'address', fallback=None)
            self.config_dic['ClientAuth']['port'] = int(config_dic.get('ClientAuth', 'port', fallback='1443'))

            # load key
            key_file = open(config_dic.get('ClientAuth', 'key_file', fallback=None), 'rb').read()
            key_file = str(key_file, 'utf-8')
            self.config_dic['ClientAuth']['key_file'] = parsePEMKey(key_file, private=True, implementations=["python"])

            # load cert
            cert_file = open(config_dic.get('ClientAuth', 'cert_file', fallback=None), 'rb').read()
            cert_file = str(cert_file, 'utf-8')
            cert_chain = X509CertChain()
            cert_chain.parsePemList(cert_file)
            self.config_dic['ClientAuth']['cert_file'] = cert_chain

    def handshake(self, connection):
        # pylint: disable=W0221
        self.logger.debug('SecureServer.handshake()')

        hs_options = hssrv_options_get(self.logger, 'ClientAuth', self.config_dic)
        request_pha = True
        require_pha = True

        try:
            _start = time_stamp()
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 5))
            connection.client_cert_required = require_pha
            connection.handshakeServer(**hs_options)
            try:
                if request_pha:
                    for _ele in connection.request_post_handshake_auth():
                        pass
            except ValueError as err_:
                # if we can't do PHA, we can't do it
                self.logger.debug(err_)

            _stop = time_stamp()
            # printgoodconnection(connection, stop-start)
        except TLSRemoteAlert as _err:
            # pylint: disable=R1705
            if _err.description == AlertDescription.user_canceled:
                self.logger.error('TLSRemoteAlert: user_canceled')
                return False
            else:
                self.logger.error('TLSRemoteAlert: %s', _err)
                return False
        except TLSLocalAlert as _err:
            # pylint: disable=R1705
            if _err.description == AlertDescription.handshake_failure:
                self.logger.error('TLSLocalAlert: Unable to negotiate mutually acceptable parameters')
                return False
            else:
                self.logger.error('TLSLocalAlert: %s', _err)
                return False

        connection.ignoreAbruptClose = True
        print(connection.session.clientCertChain)

        return True
