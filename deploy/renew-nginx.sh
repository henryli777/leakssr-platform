#!/bin/sh
set -eu

case " ${RENEWED_DOMAINS:-} " in
    *" leakssr.coinexo.top "*)
        /usr/sbin/nginx -t
        /usr/bin/systemctl reload nginx
        ;;
esac
