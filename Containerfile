FROM alpine:3

USER root

STOPSIGNAL SIGINT

LABEL org.opencontainers.image.authors="nothixy <val@hixy.tk>"

RUN apk add make \
    libpcap-dev \
    libpcap \
    bluez-dev \
    gcc \
    g++ \
    automake \
    autoconf \
    autoconf-archive \
    doxygen \
    graphviz \
    tini \
    libcap-setcap

COPY --exclude=build . /openBLAHAJ

WORKDIR /openBLAHAJ

RUN autoreconf -ivf

RUN mkdir -p /openBLAHAJ/build

WORKDIR /openBLAHAJ/build

RUN ../configure

RUN make clean

RUN make

RUN make install

RUN rm -rf /openBLAHAJ

ENTRYPOINT [ "/sbin/tini", "--", "/usr/local/bin/openBLAHAJ" ]
