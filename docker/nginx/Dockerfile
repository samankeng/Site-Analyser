# docker/nginx/Dockerfile

FROM nginx:1.21-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Create directories for certbot
RUN mkdir -p /etc/letsencrypt/live/site-analyser.com
RUN mkdir -p /var/www/certbot

# Expose ports
EXPOSE 80
EXPOSE 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

# Note: The actual nginx.conf file is mounted as a volume in docker-compose.yml