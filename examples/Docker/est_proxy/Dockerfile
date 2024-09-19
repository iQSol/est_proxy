FROM ubuntu:22.04

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    python3-pip \
    curl \
    openssl \
    patch \
    krb5-user \
    libgssapi-krb5-2 \
    libkrb5-3 \
    python3-gssapi \
 && rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# patch tlslite
COPY examples/Docker/est_proxy/tlslite-01.patch /tmp/tlslite-01.patch
RUN patch /usr/local/lib/python3.10/dist-packages/tlslite/tlsconnection.py /tmp/tlslite-01.patch

# create folders for est_proxy
RUN mkdir -p /usr/local/est_proxy/etc && \
    mkdir -p /usr/local/est_proxy/examples && \
    mkdir -p /usr/local/est_proxy/bin

COPY est_proxy/ /usr/local/est_proxy/est_proxy
COPY examples/ca_handler/ /usr/local/est_proxy/examples/ca_handler
COPY examples/est_proxy.cfg /usr/local/est_proxy/examples/
COPY est_proxyd.py /usr/local/est_proxy/bin/est_proxyd.py
RUN chmod a+rx /usr/local/est_proxy/bin/est_proxyd.py

COPY examples/Docker/est_proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh


WORKDIR /usr/local/est_proxy/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python3", "/usr/local/est_proxy/bin/est_proxyd.py", "-c", "/usr/local/est_proxy/etc/est_proxy.cfg"]
# CMD ["sleep", "infinity"]

EXPOSE 17443 17443
