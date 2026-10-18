#!/bin/sh
set -eu
KEY_FILE="${ZAP_API_KEY_FILE:-/run/secrets/zap_api_key}"
if [ ! -r "$KEY_FILE" ]; then
  echo "ZAP API key secret is missing; mount deploy/secrets/zap_api_key" >&2
  exit 78
fi
ZAP_API_KEY="$(tr -d '\r\n' < "$KEY_FILE")"
case "$ZAP_API_KEY" in
  ''|*CHANGE_ME*|*REPLACE_ME*) echo "Refusing to start ZAP with an empty/example API key" >&2; exit 78 ;;
esac
if [ "${#ZAP_API_KEY}" -lt 32 ]; then
  echo "ZAP API key must contain at least 32 characters" >&2
  exit 78
fi
# Secret is read from a Docker secret file, never written to a configuration file.
# ZAP runs only on the internal scanner network and all target traffic is chained
# through the egress proxy. Active scanner is never invoked by FIREWATCH.
exec zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config "api.key=${ZAP_API_KEY}" \
  -config "api.addrs.addr.name=.*" \
  -config "api.addrs.addr.regex=true" \
  -config "connection.proxyChain.host=egress-proxy" \
  -config "connection.proxyChain.port=3128" \
  -config "spider.postform=false" \
  -config "spider.processform=false" \
  -config "scanner.threadPerHost=1"
