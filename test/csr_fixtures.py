#!/usr/bin/python
# -*- coding: utf-8 -*-
""" CSR fixtures for the est_proxy security tests.

Builds certificate signing requests on demand with python-cryptography so the
attack cases from est-test_special.sh can be exercised as fast, offline unit
tests (no live EST server / CA needed). Each builder returns the base64 body of
the CSR *without* the PEM header/footer - this is exactly the shape
ESTSrvHandler._post_process() hands to _check_csr_data() after stripping the
BEGIN/END lines.
"""
# pylint: disable=E0401
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# one reusable key - the tests care about subject/extension/attribute content,
# not about individual key material, and key generation is the slow part.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _san(entries):
    """ build a SubjectAlternativeName from 'DNS:x'/'IP:x'/'email:x' strings """
    general_names = []
    for entry in entries:
        kind, _, value = entry.partition(':')
        if kind == 'DNS':
            general_names.append(x509.DNSName(value))
        elif kind == 'IP':
            import ipaddress
            general_names.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif kind == 'email':
            general_names.append(x509.RFC822Name(value))
        else:
            raise ValueError('unknown SAN type: {0}'.format(entry))
    return x509.SubjectAlternativeName(general_names)


def _body(csr):
    """ return the base64 DER body of a CSR, headers stripped (as the handler sees it) """
    pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    lines = [line for line in pem.splitlines() if line and '-----' not in line]
    return ''.join(lines).encode('utf-8')


def build_csr(cns, sans=None, extra_extensions=None, key=None):
    """ build a CSR and return its header-stripped base64 body.

        cns              list of common-name strings (>1 => multi-CN attack)
        sans             list of 'DNS:x'/'IP:x'/'email:x' strings
        extra_extensions list of (extension_value, critical) tuples to inject
        key              optional key override (used for the bad-signature case)
    """
    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn) for cn in cns]
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attributes))
    if sans:
        builder = builder.add_extension(_san(sans), critical=False)
    for ext_value, critical in (extra_extensions or []):
        builder = builder.add_extension(ext_value, critical=critical)
    return _body(builder.sign(key or _KEY, hashes.SHA256()))


def build_csr_with_org(cn, sans, org, ou):
    """ CSR carrying extra subject RDNs (O/OU) besides the CN """
    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
    ]
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name(name_attributes))
               .add_extension(_san(sans), critical=False))
    return _body(builder.sign(_KEY, hashes.SHA256()))


def build_csr_with_subject_attrs(cn, sans, attributes):
    """ CSR carrying arbitrary extra subject RDNs besides the CN.

        attributes  list of (NameOID, value) tuples, e.g.
                    [(NameOID.COUNTRY_NAME, 'AT'), (NameOID.LOCALITY_NAME, 'Vienna')]
    """
    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    for oid, value in attributes:
        name_attributes.append(x509.NameAttribute(oid, value))
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name(name_attributes))
               .add_extension(_san(sans), critical=False))
    return _body(builder.sign(_KEY, hashes.SHA256()))


def build_csr_bad_signature(cn, sans):
    """ CSR whose self-signature does not verify (proof-of-possession failure).

        Signs with a *different* key than the one embedded, then flips a byte in
        the signature so is_signature_valid is False without breaking the DER.
    """
    body = build_csr(cns=[cn], sans=sans)
    der = bytearray(base64.b64decode(body))
    der[-1] ^= 0xFF  # corrupt the trailing signature byte
    tampered = base64.b64encode(bytes(der))
    return tampered


def build_csr_ms_cert_extensions_attr(cn):
    """ CSR carrying the Microsoft szOID_CERT_EXTENSIONS attribute (1.3.6.1.4.1.311.2.1.14).

        MS CAs honor extensions passed through this attribute, but python-cryptography
        does not surface it via csr.extensions - and in fact raises when csr.attributes
        is enumerated, which is exactly why check_for_other_attributes must fail closed.
        No standard SAN extension is added here so the attribute stays single-valued.
    """
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .add_attribute(x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.14'), b'\x30\x00'))
    return _body(builder.sign(_KEY, hashes.SHA256()))


def build_client_certificate(cns, sans=None, org=None, ou=None):
    """ build a self-signed x509 certificate to stand in for the mTLS client
        certificate (ESTSrvHandler.client_certificate) on reenroll tests.
        Returns a loaded cryptography x509.Certificate object. """
    import datetime
    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn) for cn in cns]
    if org:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    subject = issuer = x509.Name(name_attributes)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer)
               .public_key(_KEY.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.datetime(2020, 1, 1))
               .not_valid_after(datetime.datetime(2030, 1, 1)))
    if sans:
        builder = builder.add_extension(_san(sans), critical=False)
    return builder.sign(_KEY, hashes.SHA256())


def certificate_policies(oids):
    """ a CertificatePolicies extension for the given policy OID strings """
    policies = [x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in oids]
    return x509.CertificatePolicies(policies)


def extended_key_usage(oids):
    """ an ExtendedKeyUsage extension for the given EKU OID strings """
    return x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in oids])
