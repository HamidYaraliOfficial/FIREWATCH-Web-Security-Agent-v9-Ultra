FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY squid.conf /etc/squid/squid.conf
EXPOSE 3128
HEALTHCHECK --interval=15s --timeout=5s --retries=5 CMD squidclient -h 127.0.0.1 -p 3128 mgr:info >/dev/null 2>&1 || exit 1
CMD ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
