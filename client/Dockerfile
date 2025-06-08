# client/Dockerfile - With memory optimization
FROM node:18-alpine

WORKDIR /app

# Increase memory limit for Node.js
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Copy everything
COPY . .

# Install dependencies
RUN npm install

# Build with increased memory
RUN npm run build

# Serve
RUN npm install -g serve
EXPOSE 3000
CMD ["serve", "-s", "build", "-l", "3000"]