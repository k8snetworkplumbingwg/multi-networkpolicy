# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.14 as build

# Add everything
ADD . /usr/src/macvlan-networkpolicy

RUN cd /usr/src/macvlan-networkpolicy && \
    go build ./cmd/macvlan-network-policy-node/

FROM centos:centos7
RUN yum install -y iptables-utils
COPY --from=build /usr/src/macvlan-networkpolicy/macvlan-network-policy-node /usr/bin
WORKDIR /usr/bin

ENTRYPOINT ["macvlan-networkpolicy-node"]
