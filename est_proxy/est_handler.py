# -*- coding: utf-8 -*-
""" http based est protocol handler """
import os
import ssl
import asyncio
import base64
import tempfile
import subprocess
import importlib
from hashlib import sha512
from re import search
import bcrypt
from http.server import BaseHTTPRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyrad2.client import Client
from pyrad2.radsec.client import RadSecClient
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType

from est_proxy.helper import (
    config_load,
    ca_handler_get,
    logger_setup,
    get_certificate_information,
    equal_content_list,
    san_check,
    get_cn_and_san,
    check_for_other_sans,
    check_for_other_subject_attributes,
    check_for_other_extensions,
    check_for_other_attributes,
    csr_allowed_extensions,
    equal_subjects,
    ALLOWED_SUBJECT_OIDS
)
from est_proxy.database import (
    Database,
    DEFAULT_DB_FILE
)
from est_proxy.version import __version__

RADIUS_DICTIONARY = Dictionary(os.path.join(os.path.dirname(__file__), 'radius', 'dictionary'))
MAX_BODY_SIZE = 65536

class RequestTooLarge(Exception):
    """ request body exceeds MAX_BODY_SIZE """

class ESTSrvHandler(BaseHTTPRequestHandler):
    """ serverside of est protocol handler """
    cahandler = None
    debug = False
    cfg_file = None
    logger = None
    openssl_bin = None
    connection = None
    database = None
    radius_cfg = None
    csr_allowed_ext = None
    user = None
    client_certificate = None
    protocol_version = "HTTP/1.1"
    server_version = 'est_proxy'
    sys_version = __version__

    def __init__(self, *args, **kwargs):
        """ init function """
        # get config and logger file
        try:
            self.cfg_file = args[2].__dict__['cfg_file']
        except Exception:
            self.cfg_file = 'est_proxy.cfg'
        try:
            self.logger = args[2].__dict__['logger']
        except Exception:
            self.logger = logger_setup(self.debug, cfg_file=self.cfg_file)
        if not self.openssl_bin:
            self._config_load()

        self.database = Database(DEFAULT_DB_FILE)

        try:
            # store connection settings
            self.connection = args[0]
        except Exception as err_:
            self.logger.error('ESTSrvHandler.__init__ store connection settings failed: {0}'.format(err_))
        try:
            super().__init__(*args, **kwargs)
        except Exception as err_:
            self.logger.error('ESTSrvHandler.__init__ superclass init failed: {0}'.format(err_))

    def _cacerts_get(self):
        """ get ca certificates """
        self.logger.debug('ESTSrvHandler._cacerts_get()')
        with self.cahandler(self.cfg_file, self.logger) as ca_handler:
            # get ca_certs
            ca_certs = ca_handler.ca_certs_get()
            # convert pem to pkcs#7
            if ca_certs:
                ca_pkcs7 = self._pkcs7_convert(ca_certs)
            else:
                self.logger.error('ESTSrvHandler._cacerts_get(): no cacerts returned from handler')
                ca_pkcs7 = None
        self.logger.debug('ESTSrvHandler._cacerts_get() ended with: {0}'.format(bool(ca_pkcs7)))
        return ca_pkcs7

    def _auth_check(self):
        """ split ca_certs """
        self.logger.debug('ESTSrvHandler._auth_check()')
        authenticated = False

        # Nginx client verification
        if 'X-SSL-Verified' in self.headers:
            authenticated = self._nginx_auth_check()

        # Basic and more authentication
        if 'Authorization' in self.headers and not authenticated:

            # Basic
            if self.headers['Authorization'].startswith('Basic '):
                authenticated = self._basic_auth_check()

        self.logger.debug('ESTSrvHandler._auth_check() ended with: {0}'.format(authenticated))

        return authenticated

    def _basic_auth_check(self):
        result = False

        try:
            _scheme, content = self.headers['Authorization'].split()
            credentials = base64.b64decode(content).decode('utf-8')

            username, password = credentials.split(':', 1)
        except ValueError:
            self.logger.error(' => Aborted - Malformed Authorization header.')
            return False

        user = self.database.get_user(username)

        if user:
            if user['auth_backend'] == 'local':
                authenticated = self._local_auth_check(password, user['password'])
                if authenticated and not user['password'].startswith('$2'):
                    self.logger.warning('_basic_auth_check(): user {0} still uses a deprecated password hash - rehashing to bcrypt'.format(username))
                    self.database.update_user_password(username, password)
            else:
                authenticated = self._radius_auth_check(username, password)

            if authenticated:
                self.logger.info(' => Client verified with {0} auth.'.format(user['auth_backend']))
                self.user = user
                result = True

        return result

    def _local_auth_check(self, password, stored_hash):
        """ verify a password against the stored bcrypt hash (legacy sha512 hex accepted as fallback) """
        if not stored_hash:
            return False

        if stored_hash.startswith('$2'):
            try:
                return bcrypt.checkpw(password.encode(), stored_hash.encode())
            except ValueError:
                return False

        # legacy sha512 hex fallback for pre-bcrypt stored hashes
        return sha512(password.encode()).hexdigest() == stored_hash

    def _udp_client(self):
        """ build a pyrad2 UDP RADIUS client from the configured options """
        return Client(
            server=self.radius_cfg['server'],
            authport=self.radius_cfg['port'],
            secret=self.radius_cfg['secret'].encode(),
            dict=RADIUS_DICTIONARY,
            retries=self.radius_cfg['retries'],
            timeout=self.radius_cfg['timeout'],
        )

    def _radsec_client(self):
        """ build a pyrad2 RadSec (TLS) client from the configured tls options """
        tls_versions = {
            '1.1': ssl.TLSVersion.TLSv1_1,
            '1.2': ssl.TLSVersion.TLSv1_2,
            '1.3': ssl.TLSVersion.TLSv1_3,
        }
        minimum_tls_version = tls_versions.get(self.radius_cfg['min_tls_version'], ssl.TLSVersion.TLSv1_3)

        return RadSecClient(
            server=self.radius_cfg['server'],
            port=self.radius_cfg['port'],
            secret=self.radius_cfg['secret'].encode(),
            dict=RADIUS_DICTIONARY,
            timeout=self.radius_cfg['timeout'],
            retries=self.radius_cfg['retries'],
            certfile=self.radius_cfg['certfile'],
            keyfile=self.radius_cfg['keyfile'],
            certfile_server=self.radius_cfg['certfile_server'],
            check_hostname=self.radius_cfg['check_hostname'],
            minimum_tls_version=minimum_tls_version,
        )

    def _radius_send(self, client, username, password):
        """ send an Access-Request over the given client and return the reply packet """
        request = client.create_auth_packet(code=PacketType.AccessRequest, User_Name=username, NAS_Identifier=self.radius_cfg['nas_identifier'])
        request['User-Password'] = request.pw_crypt(password)

        if self.radius_cfg['proto'] == 'radsec':
            return asyncio.run(client.send_packet(request))

        return client.send_packet(request)

    def _radius_auth_check(self, username, password):
        """ verify username/password against a RADIUS server (fails closed on any error) """
        result = False

        if not self.radius_cfg:
            self.logger.error('ESTSrvHandler._radius_auth_check(): user configured for radius auth but no [RADIUS] section found in config file')
            return result

        try:
            if self.radius_cfg['proto'] == 'radsec':
                client = self._radsec_client()
            else:
                client = self._udp_client()

            reply = self._radius_send(client, username, password)
            result = reply is not None and reply.code == PacketType.AccessAccept
        except Exception as err_:
            self.logger.error('ESTSrvHandler._radius_auth_check(): radius authentication failed with error: {0}'.format(err_))
            result = False

        return result

    def _nginx_auth_check(self):
        result = False

        if self.headers['X-SSL-Verified'] == 'SUCCESS':
            try:
                self.client_certificate = x509.load_pem_x509_certificate(self.headers['X-CLIENT-Cert'].encode('utf-8'))
                common_name = self.client_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception as err_:
                self.logger.error(' => Aborted - Could not parse the client certificate forwarded by nginx: {0}'.format(err_))
                self.client_certificate = None
                return False

            certificate_from_db = self.database.get_certificate(common_name)

            if certificate_from_db:
                self.user = self.database.get_user_by_id(certificate_from_db['user_id'])
                self.logger.info(' => Client verified by nginx.')
                result = True

        return result

    def _check_csr_data(self, csr_data) -> bool:
        result = False

        try:
            csr = x509.load_pem_x509_csr(b"-----BEGIN CERTIFICATE REQUEST-----\n" + csr_data + b"-----END CERTIFICATE REQUEST-----\n")
        except Exception:
            self.logger.error(' => Aborted - Could not load CSR.')
            return False

        if not csr.is_signature_valid:
            self.logger.error(' => Aborted - CSR signature is not valid.')
            return False

        # get the common name and san of the csr
        csr_info = get_cn_and_san(csr)

        if not csr_info['cn']:
            self.logger.error(' => Aborted - No common name could be found.')
            return False

        if len(csr_info['cn']) > 1:
            self.logger.error(' => Aborted - More than one common name in the CSR.')
            return False


        other_attributes = check_for_other_subject_attributes(csr)
        if other_attributes:
            if self.client_certificate:
                if not equal_subjects(self.logger, self.client_certificate.subject, csr.subject):
                    self.logger.error(' => Aborted - Subject of the displayed client certificate and CSR do not match.')
                    return False
            else:
                disallowed = [attribute for attribute in other_attributes if attribute.oid not in ALLOWED_SUBJECT_OIDS]
                if disallowed:
                    self.logger.error(' => Aborted - Found subject attributes other than cn/o/ou/c/l/st.')
                    return False

        if check_for_other_extensions(csr, self.csr_allowed_ext):
            self.logger.error(' => Aborted - Found a CSR extension that is not in the allowed_extensions list.')
            return False

        if check_for_other_attributes(csr):
            self.logger.error(' => Aborted - Found unexpected CSR attributes.')
            return False

        other_sans = check_for_other_sans(csr)
        if other_sans:
            self.logger.error(' => Aborted - Found other SANs then IP or DNS.')
            return False

        # check the common name and san of the csr
        cn_regex_match = san_check(self.logger, self.user['common_name_regex'], csr_info['cn'])
        if not cn_regex_match:
            self.logger.error(' => Aborted - The common name does not match the specified regex.')

        ip_regex_match = san_check(self.logger, self.user['ip_regex'], csr_info['ip'])
        if not ip_regex_match:
            self.logger.error(' => Aborted - IP entries do not match the specified regex.')

        dns_regex_match = san_check(self.logger, self.user['dns_regex'], csr_info['dns'])
        if not dns_regex_match:
            self.logger.error(' => Aborted - DNS entries do not match the specified regex.')

        if cn_regex_match and ip_regex_match and dns_regex_match:
            # checks if the client certificate for authentication and csr have the same value dns and ip address values
            if self.client_certificate:
                # add check if dns and stuff is empty
                cert_info = get_cn_and_san(self.client_certificate)

                if not equal_content_list(self.logger, cert_info['cn'], csr_info['cn']):
                    self.logger.error(' => Aborted - Common name of the displayed client certificate and CSR do not match.')
                    return False

                if not equal_content_list(self.logger, cert_info['ip'], csr_info['ip']):
                    self.logger.error(' => Aborted - IP list of the displayed client certificate and CSR do not match.')
                    return False

                if not equal_content_list(self.logger, cert_info['dns'], csr_info['dns']):
                    self.logger.error(' => Aborted - DNS list of the displayed client certificate and CSR do not match.')
                    return False

            result = True

        return result

    def _cacerts_split(self, ca_certs):
        """ split ca_certs """
        self.logger.debug('ESTSrvHandler._cacerts_split()')
        ca_certs_list = []
        if ca_certs:
            cert = ""
            for line in ca_certs.splitlines(True):
                cert += line
                if '-----END CERTIFICATE-----' in line:
                    ca_certs_list.append(cert)
                    cert = ""
        self.logger.debug('ESTSrvHandler._cacerts_split() ended with: {0} certs'.format(len(ca_certs_list)))
        return ca_certs_list

    def _cacerts_dump(self, ca_list):
        """ dump certs to file """
        self.logger.debug('ESTSrvHandler._cacerts_dump()')
        ca_file_names = []
        if isinstance(ca_list, list):
            for cert in ca_list:
                fso = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                fso.write(cert)
                fso.close()
                ca_file_names.append(fso.name)
        self.logger.debug('ESTSrvHandler._cacerts_dump() ended with: {0} certs'.format(len(ca_file_names)))
        return ca_file_names

    def _cert_enroll(self, csr):
        """ enroll cert """
        self.logger.debug('ESTSrvHandler._cert_enroll()')
        cert_pkcs7 = None
        if csr:
            with self.cahandler(self.cfg_file, self.logger, self.user['template']) as ca_handler:
                # get certs
                (error, cert, _poll_identifier) = ca_handler.enroll(csr)
                if not error and cert:
                    cert_information = get_certificate_information(cert)

                    self.database.insert_or_update_certificate(
                        cert_information['common_name'],
                        cert_information['valid_from'],
                        cert_information['valid_to'],
                        self.user['id']
                    )

                    cert_pkcs7 = self._pkcs7_convert(cert, pkcs7_clean=True)
                else:
                    if not error:
                        # fail closed - a 200 with an empty body must never leave the proxy
                        error = 'No error but no cert returned'
                    self.logger.error('ESTSrvHandler._cert_enroll(): {0}'.format(error))

        else:
            error = 'no CSR submittted'
            self.logger.error('ESTSrvHandler._cert_enroll(): no csr submitted')

        self.logger.debug('ESTSrvHandler._cert_enroll() ended with: {0}'.format(bool(cert_pkcs7)))
        return (error, cert_pkcs7)

    def _config_load(self):
        """ load config from file """
        self.logger.debug('ESTSrvHandler._config_load()')
        config_dic = config_load(self.logger, cfg_file=self.cfg_file)

        if 'DEFAULT' in config_dic and 'openssl_bin' in config_dic['DEFAULT']:
            self.openssl_bin = config_dic['DEFAULT']['openssl_bin']
        else:
            self.openssl_bin = 'openssl'

        if 'CAhandler' in config_dic and 'handler_file' in config_dic['CAhandler']:
            try:
                ca_handler_module = importlib.import_module(ca_handler_get(self.logger, config_dic['CAhandler']['handler_file']))
            except Exception as err_:
                self.logger.error('ESTSrvHandler._config_load(): CAhandler {0} could not get loaded. with error: {1}\nLoading default hander...'.format(config_dic['CAhandler']['handler_file'], err_))
                try:
                    ca_handler_module = importlib.import_module('est_proxy.ca_handler')
                except Exception:
                    self.logger.error('ESTSrvHandler._config_load():  Loading default handler failed.')
                    ca_handler_module = None
        else:
            if 'CAhandler' in config_dic:
                try:
                    ca_handler_module = importlib.import_module('est_proxy.ca_handler')
                except Exception as err_:
                    self.logger.error('ESTSrvHandler._config_load(): default CAhandler could not get loaded. err: {0}'.format(err_))
                    ca_handler_module = None
            else:
                self.logger.error('ESTSrvHandler._config_load(): CAhandler configuration missing in config file')
                ca_handler_module = None

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler

        self.radius_cfg = self._radius_config_load(config_dic)

        # extensions tolerated beyond subjectAltName (always allowed); default = those an
        # MS-WCCE template overrides anyway. certificatePolicies omitted - CA copies it verbatim
        if 'CSRvalidation' in config_dic and 'allowed_extensions' in config_dic['CSRvalidation']:
            allowed_extensions = config_dic['CSRvalidation']['allowed_extensions']
        else:
            allowed_extensions = 'keyUsage, extendedKeyUsage, basicConstraints'
        self.csr_allowed_ext = csr_allowed_extensions(self.logger, allowed_extensions)

        self.logger.debug('ca_handler: {0}'.format(ca_handler_module))
        self.logger.debug('ESTSrvHandler._config_load() ended')

    def _radius_config_load(self, config_dic):
        """ parse the [RADIUS] section into a config dict (or None if not usable) """
        # empty values count as unset so a config template can ship blank keys
        if 'RADIUS' not in config_dic:
            return None

        radius = config_dic['RADIUS']

        # missing/empty "enabled" counts as enabled so a minimal section keeps working
        if (radius.get('enabled') or 'True').lower() != 'true':
            return None

        if not radius.get('server'):
            return None

        proto = (radius.get('proto') or 'udp').lower()

        # radsec has a fixed default secret "radsec" (RFC 6614) and its own default port;
        # an explicit secret is still honored. plain udp always requires a configured secret
        if proto == 'radsec':
            default_port = 2083
            secret = radius.get('secret') or 'radsec'
        else:
            proto = 'udp'
            default_port = 1812
            if not radius.get('secret'):
                self.logger.error('ESTSrvHandler._radius_config_load(): [RADIUS] proto=udp requires a secret')
                return None
            secret = radius['secret']

        return {
            'proto': proto,
            'server': radius['server'],
            'secret': secret,
            'port': int(radius.get('port') or default_port),
            'timeout': int(radius.get('timeout') or 5),
            'retries': int(radius.get('retries') or 1),
            'nas_identifier': radius.get('nas_identifier') or 'est_proxy',
            # radsec (pyrad2 RadSecClient) TLS options
            'certfile': radius.get('certfile') or None,
            'keyfile': radius.get('keyfile') or None,
            'certfile_server': radius.get('certfile_server') or None,
            'check_hostname': (radius.get('check_hostname') or 'True').lower() == 'true',
            'min_tls_version': radius.get('min_tls_version') or '1.3',
        }

    def _pkcs7_clean(self, pkcs7_struc):
        """ remove cert header and footer """
        self.logger.debug('ESTSrvHandler._pkcs7_clean()')
        if isinstance(pkcs7_struc, bytes):
            pkcs7_struc = pkcs7_struc.decode('utf-8')
        if pkcs7_struc and isinstance(pkcs7_struc, str):
            # remove pkcs7 start end end tags
            pkcs7_struc = pkcs7_struc.replace('-----BEGIN PKCS7-----\n', '')
            # do not remove CR from end tag as it must be part of the content
            pkcs7_struc = pkcs7_struc.replace('-----END PKCS7-----', '')
        return pkcs7_struc

    def _pkcs7_convert(self, ca_certs, pkcs7_clean=True):
        """ convert to pkcs#7 """
        self.logger.debug('ESTSrvHandler._pkcs7_convert()')

        pkcs7_struc = None
        if ca_certs:
            # split pem-chain into certs
            ca_list = self._cacerts_split(ca_certs)
            # dump certs into temporary files
            file_names = self._cacerts_dump(ca_list)

            if self.openssl_bin and file_names:
                fso = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                pkcs7_file = fso.name
                fso.close()

                # create command-line to convert
                openssl_cmd = self._opensslcmd_build(file_names, pkcs7_file)

                # run command and capture return code
                rcode = subprocess.call(openssl_cmd)
                if rcode == 0:
                    with open(pkcs7_file, 'r', encoding='utf-8') as fso:
                        pkcs7_struc = fso.read()

                if pkcs7_struc and pkcs7_clean:
                    pkcs7_struc = self._pkcs7_clean(pkcs7_struc)

                # add outfile to list and delete all files
                file_names.append(pkcs7_file)
                self._tmpfiles_clean(file_names)

        return pkcs7_struc

    def _tmpfiles_clean(self, file_name_list):
        """ clean files """
        self.logger.debug('ESTSrvHandler._tmpfiles_clean()')
        for file_name in file_name_list:
            try:
                os.remove(file_name)
            except Exception as err:
                self.logger.error('ESTSrvHandler._tmpfiles_clean() failed for {0} with error: {1}'.format(file_name, err))

    def _opensslcmd_build(self, file_name_list, pkcs7_file):
        """ build ssl cmd """
        # convert to list if string or byte
        if isinstance(file_name_list, str):
            file_name_list = [file_name_list]
        elif isinstance(file_name_list, bytes):
            file_name_list = [file_name_list.decode('utf-8')]
        # create list of openssl parameters
        cmd_list = [self.openssl_bin, 'crl2pkcs7', '-nocrl', '-out', pkcs7_file]
        for file_name in file_name_list:
            cmd_list.extend(['--certfile', file_name])
        return cmd_list

    def _set_response(self, code=404, content_type='text/html', clength=0, encoding=None):
        """ set response method """
        self.send_response(code)
        if content_type:
            self.send_header('Content-Type', content_type)
        if encoding:
            self.send_header('Content-Transfer-Encoding', encoding)
        if clength:
            self.send_header('Content-Length', clength)
        self.send_header('Connection', 'close')
        self.end_headers()

    def log_message(self, format, *args):
        self.logger.info('%s', format % args)

    def _get_process(self):
        """ main method to process get requests """
        self.logger.debug('ESTSrvHandler._get_process %s', self.path)
        content = None
        content_type = None
        content_length = 0
        encoding = None

        if self.path == '/.well-known/est/cacerts':
            ca_certs = self._cacerts_get()
            if ca_certs:
                code = 200
                content_type = 'application/pkcs7-mime'
                content = ca_certs
                encoding = 'base64'
            else:
                code = 500
                content_type = 'text/html'
        elif self.path == '/.well-known/est/csrattrs':
            code = 404
            content = 'Not implemented.\n'
        else:
            code = 404
            content_type = 'text/html'
            content = 'An unknown error has occured.\n'

        if content:
            content_length = len(str(content))
            content = content.encode('utf8')

        return(code, content_type, content_length, encoding, content)

    def _post_process(self, data):
        """ main method to process post requests """
        self.logger.debug('ESTSrvHandler._post_process %s', self.path)
        content = None
        content_length = 0
        content_type = None
        encoding = None
        code = 400

        certificate_authenticated = False

        # check if connection is properly authenticated
        connection_authenticated = self._auth_check()

        if connection_authenticated and self.user:
            # Replace csr headers if the exist
            if data and search(b"-----BEGIN CERTIFICATE REQUEST-----\n", data):
                data = data.replace(b'-----BEGIN CERTIFICATE REQUEST-----\n', b'').replace(b'-----END CERTIFICATE REQUEST-----\n', b'')

            certificate_authenticated = self._check_csr_data(data)

        if connection_authenticated:
            if certificate_authenticated:
                if data and self.path in ('/.well-known/est/simpleenroll', '/.well-known/est/simplereenroll'):
                    # enroll certificate
                    (error, cert) = self._cert_enroll(data)
                    if not error:
                        self.logger.info(' => Success - The requested certificate was successfully enrolled.')
                        code = 200
                        content_type = 'application/pkcs7-mime; smime-type=certs-only'
                        content = cert
                        encoding = 'base64'
                    else:
                        self.logger.info(' => Aborted - A problem ocurred while enrolling the certificate.')
                        content = 'A problem ocurred while enrolling the certificate.\n'
                        code = 500
                else:
                    # valid CSR but unknown path - same response as _get_process()
                    code = 400
                    content = 'An unknown error has occured.\n'
            elif self.path in ('/.well-known/est/serverkeygen', '/.well-known/est/fullcmc'):
                code = 404
                content = 'Not implemented.\n'
            else:
                code = 400
                if data:
                    if self.client_certificate:
                        content = 'A problem ocurred while checking the CSR and client certificate.\nView the EST proxy log for more information!\n'
                    else:
                        content = 'A problem ocurred while checking the CSR. View the EST proxy log for more information!\n'
                else:
                    content = 'No data had been send.\n'
        else:
            self.logger.info(' => Aborted - The client could not be authenticated.')
            code = 401
            content = 'The server was unable to authorize the request.\n'

        if content:
            content_length = len(str(content))
            content = content.encode('utf8')

        return(code, content_type, content_length, encoding, content)

    # pylint: disable=C0103
    def do_GET(self):
        """ this is a http get """
        self.logger.debug('ESTSrvHandler.do_GET %s path: %s', self.client_address, self.path)
        # process request
        (code, content_type, content_length, encoding, content) = self._get_process()
        # write response
        self._set_response(code, content_type, content_length, encoding)
        if content:
            self.wfile.write(content)

    def _read_exact(self, length):
        """ read exactly length bytes from rfile; tlslite hands rfile over as an
            unbuffered socket.SocketIO, so a single read() may return short """
        data = b''
        while len(data) < length:
            block = self.rfile.read(length - len(data))
            if not block:
                # EOF - caller decides how to handle the short result
                break
            data += block
        return data

    def _chunked_body_read(self):
        """ RFC 7230 dechunking of the request body """
        self.logger.debug('ESTSrvHandler._chunked_body_read()')
        chunks = []
        total_length = 0
        while True:
            raw_line = self.rfile.readline(1024)
            if raw_line and not raw_line.endswith(b'\n'):
                raise ValueError('chunk size line too long')
            # a chunk-size line may carry extensions ("5;name=val") - ignore them
            size_part = raw_line.strip().split(b';', 1)[0]
            if not search(rb'^[0-9A-Fa-f]{1,7}$', size_part):
                raise ValueError('invalid chunk size line')
            chunk_length = int(size_part, 16)
            if chunk_length == 0:
                # consume optional trailer lines up to the terminating empty line
                for _ in range(100):
                    if not self.rfile.readline(1024).strip():
                        break
                else:
                    raise ValueError('too many trailer lines')
                break
            if total_length + chunk_length > MAX_BODY_SIZE:
                raise RequestTooLarge()
            chunk = self._read_exact(chunk_length)
            if len(chunk) != chunk_length:
                raise ValueError('premature end of chunked body')
            # every chunk is terminated by CRLF
            if self.rfile.readline(1024).strip():
                raise ValueError('missing chunk terminator')
            chunks.append(chunk)
            total_length += chunk_length
        post_data = b''.join(chunks)
        self.logger.debug('ESTSrvHandler._chunked_body_read() ended with: {0} bytes'.format(len(post_data)))
        return post_data

    def _body_read(self):
        """ read the request body; returns (error_response, post_data) """
        post_data = None
        error = None

        if "Content-Length" in self.headers and "Transfer-Encoding" in self.headers:
            # ambiguous framing (request smuggling vector) - reject per RFC 7230 3.3.3
            return ((400, 'Both Content-Length and Transfer-Encoding present.\n'), None)

        if "Content-Length" in self.headers:
            try:
                content_length = int(self.headers['Content-Length'])
            except ValueError:
                return ((400, 'Invalid Content-Length header.\n'), None)
            if content_length > MAX_BODY_SIZE:
                error = (413, 'Request body too large.\n')
            elif content_length > 0:
                post_data = self._read_exact(content_length)
                if len(post_data) != content_length:
                    error = (400, 'Malformed request body.\n')
                    post_data = None
        elif "chunked" in self.headers.get("Transfer-Encoding", ""):
            self.logger.debug('ESTSrvHandler._body_read() chunk encoding detected...')
            try:
                post_data = self._chunked_body_read()
            except RequestTooLarge:
                error = (413, 'Request body too large.\n')
            except ValueError as err_:
                self.logger.error('ESTSrvHandler._body_read() malformed chunked body: {0}'.format(err_))
                error = (400, 'Malformed chunked request body.\n')

        return (error, post_data)

    def do_POST(self):
        """ this is a http post """
        self.logger.debug('ESTSrvHandler.do_POST %s path: %s', self.client_address, self.path)

        (body_error, post_data) = self._body_read()
        if body_error:
            (code, error_content) = body_error
            content = error_content.encode('utf8')
            self._set_response(code, 'text/html', len(content))
            self.wfile.write(content)
            return

        (code, content_type, content_length, encoding, content) = self._post_process(post_data)

        # write response
        self._set_response(code, content_type, content_length, encoding)
        if content:
            self.wfile.write(content)
