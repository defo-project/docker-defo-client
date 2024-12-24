FROM ubuntu:24.04

# hadolint ignore=DL3008
RUN mkdir -p /code && \
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    git && \
    apt-get update && apt-get build-dep -y \
    libssl-dev \
    curl \
    && rm -rf /var/apt/lists/*

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV LDFLAGS="-Wl,-rpath,/usr/local/lib"
ENV CFLAGS="-I/usr/local/include"
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

WORKDIR /code
# hadolint ignore=DL3003,DL3013,SC1091
RUN git clone --depth=1 https://github.com/defo-project/openssl openssl && \
    cd openssl && \
    ./config && \
    make -j8 && \
    make install_sw && \
    ldconfig && \
    cd .. && rm -rf openssl && \
    git clone --depth=1 https://github.com/defo-project/curl && \
    cd curl && \
    autoreconf -fi && \
    ./configure --with-openssl=/usr/local \
    --enable-ech --enable-httpsrr \
    --enable-debug && \
    make -j8 && \
    make install && \
    cd .. && rm -rf curl && \
    git clone --depth=1 https://github.com/irl/cpython.git && \
    cd cpython && \
    git checkout ech && \
    ./configure --with-openssl=/usr/local && \
    make -j8 && \
    make install && \
    cd .. && rm -rf cpython && \
    mkdir -p /code/test-code && \
    /usr/local/bin/python3.13 -m venv /code/venv && \
    . /code/venv/bin/activate && \
    pip install --no-cache-dir certifi dnspython httptools

WORKDIR /code/test-code
COPY ./run_command.sh /code/test-code/run_command.sh
COPY ./pyclient.py /code/test-code/pyclient.py
COPY ./targets.json /code/test-code/targets.json
RUN chmod +x /code/test-code/run_command.sh

ENTRYPOINT ["/code/test-code/run_command.sh"]
