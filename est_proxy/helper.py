#!/usr/bin/python
# -*- coding: utf-8 -*-
""" helper functions for est_proxy """
from __future__ import print_function
from datetime import datetime, timezone
import os
import logging
import configparser
import base64
import textwrap
from re import fullmatch
import pytz
from cryptography import x509
from cryptography.x509.oid import (
	NameOID,
	ExtensionOID,
	AttributeOID
)
from tlslite import (
	SessionCache,
	HandshakeSettings
)
from tlslite.constants import (
	CipherSuite,
	HashAlgorithm,
	SignatureAlgorithm,
	GroupName,
	SignatureScheme
)

# subject RDNs (besides CN) a CSR may carry on enroll
ALLOWED_SUBJECT_OIDS = {
    NameOID.ORGANIZATION_NAME,
    NameOID.ORGANIZATIONAL_UNIT_NAME,
    NameOID.COUNTRY_NAME,
    NameOID.LOCALITY_NAME,
    NameOID.STATE_OR_PROVINCE_NAME,
}

# friendly extension names accepted in [CSRvalidation] allowed_extensions
# subjectAltName is always allowed and does not need to be listed
CSR_EXTENSION_NAMES = {
    'keyusage': ExtensionOID.KEY_USAGE,
    'extendedkeyusage': ExtensionOID.EXTENDED_KEY_USAGE,
    'basicconstraints': ExtensionOID.BASIC_CONSTRAINTS,
    'certificatepolicies': ExtensionOID.CERTIFICATE_POLICIES,
}

def b64decode_pad(logger, string):
    """ b64 decoding and padding of missing "=" """
    logger.debug('b64decode_pad()')
    try:
        b64dec = base64.urlsafe_b64decode(string + '=' * (4 - len(string) % 4))
    except Exception:
        b64dec = b'ERR: b64 decoding error'
    return b64dec.decode('utf-8')

def b64_url_recode(logger, string):
    """ recode base64_url to base64 """
    logger.debug('b64_url_recode()')
    padding_factor = (4 - len(string) % 4) % 4
    string = convert_byte_to_string(string)
    string += "="*padding_factor
    result = str(string).translate(dict(zip(map(ord, u'-_'), u'+/')))
    return result

def equal_content_list(logger, list1: list, list2: list) -> bool:
    logger.debug(f"Compare: {list1} - {list2}")

    diff1 = set(list1) - set(list2)
    diff2 = set(list2) - set(list1)

    if not diff1 and not diff2:
        return True

    return False

def san_check(logger, pattern: str, san_list: list) -> bool:

    if pattern:
        # a filter only constrains values that are present; an empty san_list carries nothing
        # attacker-controlled, so it passes. ('^.*' means any value including none)
        for san_item in san_list:
            # fullmatch, not search - else 'test-client-01' would match 'test-client-01.evil.com'
            if not fullmatch(pattern, str(san_item)):
                logger.info('san_check(): "%s" does not match the configured pattern "%s" - rejecting.', str(san_item), pattern)
                return False

    return True

def get_cn_and_san(data):

    try:
        # collect every CN RDN - a CSR may carry more than one and each lands in the cert
        data_object_cn = [attribute.value for attribute in data.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    except Exception:
        data_object_cn = []

    try:
        data_extensions = data.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except Exception:
        data_extensions = None

    if data_extensions:
        data_object_ip = data_extensions.value.get_values_for_type(x509.IPAddress)
        data_object_dns = data_extensions.value.get_values_for_type(x509.DNSName)
    else:
        data_object_ip = []
        data_object_dns = []

    return {
        'cn': data_object_cn,
        'ip': data_object_ip,
        'dns': data_object_dns
    }

def check_for_other_sans(data):
    other_sans = []
    try:
        sans = data.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        sans = []

    for san in sans:
        if not isinstance(san, (x509.DNSName, x509.IPAddress)):
            other_sans.append(san)

    return other_sans

def check_for_other_subject_attributes(data):
    """
        return subject RDNs that are not a common name (O, OU, ...)
    """
    return [attribute for attribute in data.subject if attribute.oid != NameOID.COMMON_NAME]

def equal_subjects(logger, subject1, subject2) -> bool:
    """
        compare two x509 subjects as an unordered set of (oid, value) pairs.
        used on reenroll to allow a CSR to carry extra subject attributes (O/OU/...)
        as long as they are identical to the presented client certificate's subject.
    """
    set1 = {(attribute.oid, attribute.value) for attribute in subject1}
    set2 = {(attribute.oid, attribute.value) for attribute in subject2}
    logger.debug(f"Compare subjects: {set1} - {set2}")
    return set1 == set2

def csr_allowed_extensions(logger, extension_string):
    """ turn the config string "keyUsage, extendedKeyUsage, ..." into a set of
        tolerated extension OIDs. subjectAltName is always included. A name may
        also be a dotted OID. Unknown/blank entries are skipped with a log line. """
    allowed = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
    for raw in (extension_string or '').split(','):
        name = raw.strip()
        if not name:
            continue
        key = name.lower()
        if key in CSR_EXTENSION_NAMES:
            allowed.add(CSR_EXTENSION_NAMES[key])
        elif name[0].isdigit():
            try:
                allowed.add(x509.ObjectIdentifier(name))
            except ValueError:
                logger.error('csr_allowed_extensions(): invalid OID "%s" - ignoring.', name)
        else:
            logger.error('csr_allowed_extensions(): unknown CSR extension "%s" - ignoring.', name)
    return allowed

def check_for_other_extensions(data, allowed_oids=None):
    """ return CSR extensions that are not on the allowlist.
        allowed_oids defaults to {subjectAltName}; the caller passes a wider set
        built by csr_allowed_extensions() from config. fails closed: a CSR whose
        extensions cannot be parsed (e.g. duplicate extensions) yields a non-empty
        result so the caller rejects it. """
    if allowed_oids is None:
        allowed_oids = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
    try:
        extensions = list(data.extensions)
    except Exception:
        return ['unparseable extensions']

    return [extension for extension in extensions if extension.oid not in allowed_oids]

def check_for_other_attributes(data):
    """
        return CSR attributes that are not on the allowlist.
        only extensionRequest and challengePassword are permitted; anything else
        (notably the Microsoft szOID_CERT_EXTENSIONS attribute, which MS CAs honor
        but python-cryptography does not surface as an extension) is rejected.
        fails closed on parse errors.
    """
    allowed_oids = {
        # PKCS#9 extensionRequest - the standard way to carry extensions in a CSR
        x509.ObjectIdentifier('1.2.840.113549.1.9.14'),
        AttributeOID.CHALLENGE_PASSWORD,
    }
    try:
        attributes = list(data.attributes)
    except Exception:
        return ['unparseable attributes']

    return [attribute for attribute in attributes if attribute.oid not in allowed_oids]

def get_certificate_information(pem_data):

    # Load the certificate
    cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'))

    return {
        "common_name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "valid_from": cert.not_valid_before_utc,
        "valid_to": cert.not_valid_after_utc
        }

def build_pem_file(logger, existing, certificate, wrap, csr=False):
    """ construct pem_file """
    logger.debug('build_pem_file()')
    if csr:
        pem_file = '-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n'.format(textwrap.fill(convert_byte_to_string(certificate), 64))
    else:
        if existing:
            if wrap:
                pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(existing), textwrap.fill(convert_byte_to_string(certificate), 64))
            else:
                pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(existing), convert_byte_to_string(certificate))
        else:
            if wrap:
                pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(textwrap.fill(convert_byte_to_string(certificate), 64))
            else:
                pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(certificate))
    return pem_file

def ca_handler_get(logger, ca_handler_name):
    """ turn handler-filename into a python path """
    logger.debug('ca_handler_get({0})'.format(ca_handler_name))
    ca_handler_name = ca_handler_name.rstrip('.py')
    ca_handler_name = ca_handler_name.replace('/', '.')
    ca_handler_name = ca_handler_name.replace('\\', '.')
    logger.debug('ca_handler_get() ended with: {0}'.format(ca_handler_name))
    return ca_handler_name

def config_load(logger=None, mfilter=None, cfg_file=os.path.dirname(__file__)+'/'+'est_proxy.cfg'):
    """ small configparser wrappter to load a config file """
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.RawConfigParser()
    config.optionxform = str
    try:
        config.read(cfg_file)
    except Exception:
        config = {}

    return config

def connection_log(logger, connection, seconds):
    """ a really ugly function i need to replace at a later stage """
    logger.debug('Remote end: %s', connection.getpeername())
    logger.debug(' Handshake time: %.3f seconds', seconds)
    logger.debug(" Version: %s", connection.getVersionName())
    logger.debug(" Cipher: %s %s", connection.getCipherName(), connection.getCipherImplementation())
    logger.debug(" Ciphersuite: %s", CipherSuite.ietfNames[connection.session.cipherSuite])

    if connection.session.clientCertChain:
        logger.debug(" Client X.509 SHA1 fingerprint: %s", connection.session.clientCertChain.getFingerprint())
    else:
        logger.debug(" No client certificate provided by peer")
    if connection.session.serverCertChain:
        logger.debug(" Server X.509 SHA1 fingerprint: %s", connection.session.serverCertChain.getFingerprint())
    if connection.version >= (3, 3) and connection.serverSigAlg is not None:
        scheme = SignatureScheme.toRepr(connection.serverSigAlg)
        if scheme is None:
            scheme = "{1}+{0}".format(HashAlgorithm.toStr(connection.serverSigAlg[0]), SignatureAlgorithm.toStr(connection.serverSigAlg[1]))
        logger.debug(" Key exchange signature: %s", scheme)
    if connection.ecdhCurve is not None:
        logger.debug(" Group used for key exchange: %s", GroupName.toStr(connection.ecdhCurve))
    if connection.dhGroupSize is not None:
        logger.debug(" DH group size: %s bits", connection.dhGroupSize)
    if connection.session.serverName:
        logger.debug(" SNI: %s", connection.session.serverName)
    if connection.session.appProto:
        logger.debug(" Application Layer Protocol negotiated: %s", connection.session.appProto.decode('utf-8'))
    logger.debug(" Next-Protocol Negotiated: %s", connection.next_proto)
    logger.debug(" Encrypt-then-MAC: %s", connection.encryptThenMAC)
    logger.debug(" Extended Master Secret: %s", connection.extendedMasterSecret)

def convert_byte_to_string(value):
    """ convert a variable to string if needed """
    if hasattr(value, 'decode'):
        try:
            return value.decode()
        except Exception:
            return value
    else:
        return value

def convert_string_to_byte(value):
    """ convert a variable to byte if needed """
    if hasattr(value, 'encode'):
        result = value.encode()
    else:
        result = value
    return result

def logger_setup(debug, cfg_file=None):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    # define log format
    try:
        config_dic = config_load(cfg_file=cfg_file)
        log_format = config_dic.get('Logging', 'log_format', fallback='%(message)s')
    except Exception:
        log_format = '%(message)s'

    logging.basicConfig(format=log_format, datefmt="%Y-%m-%d %H:%M:%S", level=log_mode)
    logger = logging.getLogger('est_proxy')
    return logger

def hssrv_options_get(logger, config_dic):
    """ get parameters for handshake server """
    logger.debug('hssrv_options_get()')

    hs_settings = HandshakeSettings()
    hs_settings.minVersion = (3, 3)

    option_dic = {}
    if 'Daemon' in config_dic:
        if 'cert_file' in config_dic['Daemon'] and 'key_file' in config_dic['Daemon']:
            option_dic['certChain'] = config_dic['Daemon']['cert_file']
            option_dic['privateKey'] = config_dic['Daemon']['key_file']
            option_dic['sessionCache'] = SessionCache()
            option_dic['alpn'] = [bytearray(b'http/1.1')]
            option_dic['settings'] = hs_settings
            option_dic['sni'] = None
        else:
            logger.error('Helper.hssrv_options_get(): incomplete Daemon configuration in config file')
    else:
        logger.error('Helper.hssrv_options_get(): Daemon specified but not configured in config file')

    logger.debug('hssrv_options_get() ended')
    return option_dic

def uts_now():
    """ return unixtimestamp in utc """
    return int(datetime.now(timezone.utc).timestamp())

def uts_to_date_utc(uts, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert unix timestamp to date format """
    return datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)
