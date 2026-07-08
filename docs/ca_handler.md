<!-- markdownlint-disable  MD013 -->
<!-- wiki-title How to create your own CA Handler -->
# How to create your own CA-Handler

Creating your own CA-Handler should be pretty easy.  All you need to do is to create your own ca_handler.py with a "CAhandler" class containing the following methods required by `est_proxy`:

- __ca_certs_get__: to fetch CA certificates from CA server
- __enroll__: to enroll a new certificate from CA server
- __poll__: to poll a pending certificate request from CA server __(NOT IMPLEMENTED YET!)__

The [skeleton_ca_handler.py](../examples/ca_handler/skeleton_ca_handler.py) contains a skeleton which can be used to create customized ca_handlers.

The below skeleton describes the different input parameters given by est_proxy as well as the expected return values.

```python
class CAhandler(object):
    """ CA handler """

    def __init__(self, debug=None, logger=None):
        """
        input:
            debug - debug mode (True/False)
            logger - log handler
        """
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        """ Makes CAhandler a context manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def ca_certs_get(self):
            """ fetch exsting certificates """
            input: None

            output: cert_bundle - certificate chain in pem format

            self.logger.debug('CAhandler.ca_certs_get()')
            ...
            return cert_bundle

    def enroll(self, csr):
        """ enroll certificate """
        input:
            csr - csr in pkcs10 format

        output:
            error - error message during cert enrollment (None in case no error occured)
            certificate - certificate chain in pem format
            poll_identifier - callback identifier to lookup enrollment request in case the CA server does not issue
                              certificate immediately. This identifier will be used by the polling method check if
                              a CSR got accepted

        self.logger.debug('Certificate.enroll()')
        ...
        self.logger.debug('Certificate.enroll() ended')

        return(error, certificate, poll_identifier)

    def poll(self, poll_identifier, csr):
        """ poll pending status of pending CSR and download certificates """
        input:
            poll_identifier - poll_identifier
            csr - csr

        output:
            error - error message during cert polling (None in case no error occured)
            certificate - certificate
            poll_identifier - (updated) callback identifier - will be updated in database for later lookups
            rejected - indicates of request has been rejected by CA admistrator - in case of a request rejection
                       the corresponding order status will be set to "invalid" state

        self.logger.debug('CAhandler.poll()')
        ...
        return(error, certificate, poll_identifier, rejected)
```

You can add additional methods according to your needs. You can also add configuration options to est_proxy.cfg allowing you to configure the ca_handler according to your needs.
Check the [mswcce_ca_handler.py](../examples/ca_handler/mswcce_ca_handler.py) especially the `_config_load()` method for further details.
