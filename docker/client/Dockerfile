# docker/client/Dockerfile

# Build stage
FROM node:16-alpine as build

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code
COPY . .

# Build the React application
RUN npm run build

# Production stage
FROM nginx:1.21-alpine

# Copy the build output from build stage
COPY --from=build /app/build /usr/share/nginx/html

# Copy custom nginx configuration
COPY ../docker/client/nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]