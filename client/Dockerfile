# client/Dockerfile - Debug version
FROM node:18-alpine

WORKDIR /app

# Copy everything
COPY . .

# Debug: Check what files we have
RUN echo "=== Files in /app ===" && ls -la
RUN echo "=== Files in /app/public ===" && ls -la public/ || echo "No public folder!"
RUN echo "=== Files in /app/src ===" && ls -la src/ || echo "No src folder!"

# Install dependencies
RUN npm install

# Debug: Check package.json scripts
RUN echo "=== Package.json scripts ===" && cat package.json | grep -A 10 '"scripts"'

# Debug: Try to build with verbose output
RUN npm run build 2>&1 || (echo "Build failed, showing more details:" && npm run build --verbose 2>&1)

# If build succeeds, continue
RUN npm install -g serve
EXPOSE 3000
CMD ["serve", "-s", "build", "-l", "3000"]