FROM node:18-alpine
RUN npm install -g local-cors-proxy
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

