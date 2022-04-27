FROM alpine:3.15.4
RUN apk add --no-cache npm
RUN npm install -g local-cors-proxy
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

