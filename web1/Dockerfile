FROM nginx:stable-alpine3.24

RUN apk add --no-cache iproute2

COPY index.html /usr/share/nginx/html/index.html
COPY nginx.conf /etc/nginx/conf.d/default.conf
