# Copyright (c) 2024 The Jaeger Authors.
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.21.0 AS cert
RUN apk add --update --no-cache ca-certificates mailcap

FROM alpine:3.21.0
RUN apk add --no-cache curl && \
    rm -rf /var/cache/apk/*
COPY --from=cert /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cert /etc/mime.types /etc/mime.types
