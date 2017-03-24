# Dockerfile example for debian Signal Sciences agent container

FROM ilagnev/alpine-nginx-lua:latest
MAINTAINER Signal Sciences Corp. 

RUN mkdir -p /opt/sigsci/nginx

COPY contrib/sigsci-module/MessagePack.lua /opt/sigsci/nginx/MessagePack.lua
COPY contrib/sigsci-module/SignalSciences.lua /opt/sigsci/nginx/SignalSciences.lua
COPY contrib/sigsci-module/sigsci_init.conf /opt/sigsci/nginx/sigsci_init.conf
COPY contrib/sigsci-module/sigsci_module.conf /opt/sigsci/nginx/sigsci_module.conf
COPY contrib/sigsci-module/sigsci.conf /opt/sigsci/nginx/sigsci.conf
COPY contrib/sigsci-agent/sigsci-agent /usr/sbin/sigsci-agent
COPY contrib/sigsci-agent/sigsci-agent-diag /usr/sbin/sigsci-agent-diag

COPY contrib/nginx.conf /etc/nginx/nginx.conf

ADD . /app
RUN apk update && apk --no-cache add apr apr-util ca-certificates openssl && rm -rf /var/cache/apk/*
RUN chmod +x /usr/sbin/sigsci-agent; chmod +x /usr/sbin/sigsci-agent-diag; chmod +x /app/start.sh

ENTRYPOINT ["/app/start.sh"]

