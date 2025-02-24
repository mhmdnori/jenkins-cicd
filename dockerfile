FROM nginx:stable-alpine3.20-perl

COPY index.html /usr/share/nginx/html/

EXPOSE 80

RUN chmod 644 /usr/share/nginx/html/index.html

CMD ["nginx", "-g", "daemon off;"]
