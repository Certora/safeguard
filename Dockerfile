FROM golang:1.22-bullseye AS builder

# Choose which plugin to use
ARG PLUGIN_NAME

COPY go.mod /go-ethereum/
COPY go.sum /go-ethereum/
RUN cd /go-ethereum && go mod download

ADD . /go-ethereum
RUN cd /go-ethereum/safeguard && \
    export SAFEGUARD_OBJ_PATH=$(pwd)/safeguard.so && \
    ./build_plugin.sh $PLUGIN_NAME && \
    cd /go-ethereum && \
    go run build/ci.go install ./cmd/geth

# Build geth
FROM ubuntu:22.04 AS geth

COPY --from=builder /go-ethereum/safeguard/safeguard.so /go-ethereum/build/bin/geth /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV SAFEGUARD_PLUGIN_PATH=/usr/local/bin/safeguard.so \
    SAFEGUARD_OBJ_PATH=/usr/local/bin/safeguard.so \
    SAFEGUARD_LOAD_INITIAL=1 \
    SAFEGUARD_MODE=STATIC

EXPOSE 8545 8546 30303 30303/udp

ENTRYPOINT ["geth"]

# Build dashboard
FROM python:3.11-slim AS dashboard

ARG PLUGIN_NAME
ADD ./safeguard/$PLUGIN_NAME/app.py /home/safeguard/plugin/app.py
ADD ./dashboard /home/dashboard

# Install python dependencies
RUN pip install -r /home/dashboard/requirements.txt

EXPOSE 8000

ENTRYPOINT ["gunicorn", "home.safeguard.plugin.app:app", "-b", "0.0.0.0:8000"]
