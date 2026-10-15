FROM nginx:1.30.3-alpine

RUN apk add --no-cache iproute2

COPY index.html /usr/share/nginx/html/index.html
COPY nginx.conf /etc/nginx/conf.d/default.conf
