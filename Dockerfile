# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.14 as build

# Add everything
ADD . /usr/src/multi-networkpolicy

RUN cd /usr/src/multi-networkpolicy && \
    go build ./cmd/multi-networkpolicy-node/

FROM centos:centos7
RUN yum install -y iptables-utils
COPY --from=build /usr/src/multi-networkpolicy/multi-networkpolicy-node /usr/bin
WORKDIR /usr/bin

ENTRYPOINT ["multi-networkpolicy-node"]
