# client/Dockerfile - Secure version for Railway
FROM node:18-alpine3.18

# Create app directory and non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app

# Copy package files with proper ownership
COPY --chown=nextjs:nodejs package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code with proper ownership
COPY --chown=nextjs:nodejs . .

# Build the React app
RUN npm run build

# Install serve to serve static files
RUN npm install -g serve@14

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Serve the built app
CMD ["serve", "-s", "build", "-l", "3000"]