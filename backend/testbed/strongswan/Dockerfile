# strongSwan lab gateway: charon + swanctl, tcpdump for capture, and simple traffic tools.
FROM alpine:3.20

RUN apk add --no-cache strongswan tcpdump iperf3 curl iputils iproute2 python3 bash gettext

COPY strongswan.conf /etc/strongswan.conf
COPY swanctl.conf.tmpl /lab/swanctl.conf.tmpl
COPY entrypoint.sh traffic.sh run-scenario.sh /lab/
RUN chmod +x /lab/*.sh

ENTRYPOINT ["/lab/entrypoint.sh"]
