FROM python:3.12-alpine AS builder

RUN apk add --no-cache build-base krb5-dev libffi-dev

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --prefix=/install -r /tmp/requirements.txt

FROM python:3.12-alpine

RUN apk add --no-cache \
    curl \
    openssl \
    krb5

COPY --from=builder /install /usr/local

# create folders for est_proxy
RUN mkdir -p /usr/local/est_proxy/etc && \
    mkdir -p /usr/local/est_proxy/examples && \
    mkdir -p /usr/local/est_proxy/bin

COPY est_proxy/ /usr/local/est_proxy/est_proxy
COPY examples/ca_handler/ /usr/local/est_proxy/examples/ca_handler
COPY examples/est_proxy.cfg /usr/local/est_proxy/examples/
COPY est_proxyd.py /usr/local/est_proxy/bin/est_proxyd.py
RUN chmod a+rx /usr/local/est_proxy/bin/est_proxyd.py
COPY tools/db_update.py /usr/local/est_proxy/bin/db_update.py
RUN chmod a+rx /usr/local/est_proxy/bin/db_update.py

COPY examples/Docker/est_proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh


WORKDIR /usr/local/est_proxy/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python3", "/usr/local/est_proxy/bin/est_proxyd.py", "-c", "/usr/local/est_proxy/etc/est_proxy.cfg"]
# CMD ["sleep", "infinity"]

EXPOSE 17443 17443
