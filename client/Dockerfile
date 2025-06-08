# client/Dockerfile - Better error debugging
FROM node:18-alpine

WORKDIR /app

# Copy everything
COPY . .

# Debug: Check what files we have
RUN ls -la
RUN ls -la public/ || echo "No public folder"
RUN ls -la src/ || echo "No src folder"

ARG CACHE_BUST=1

# Set build-time environment variables
ARG REACT_APP_GOOGLE_CLIENT_ID
ARG REACT_APP_GITHUB_CLIENT_ID  
ARG REACT_APP_MICROSOFT_CLIENT_ID

# Make them available to the build process
ENV REACT_APP_GOOGLE_CLIENT_ID=$REACT_APP_GOOGLE_CLIENT_ID
ENV REACT_APP_GITHUB_CLIENT_ID=$REACT_APP_GITHUB_CLIENT_ID
ENV REACT_APP_MICROSOFT_CLIENT_ID=$REACT_APP_MICROSOFT_CLIENT_ID

# Install dependencies
RUN npm install

# Show package.json build script
RUN cat package.json | grep -A 5 '"build"'

# Try build and capture all output
RUN npm run build > build.log 2>&1 || (echo "=== BUILD FAILED - Log contents:" && cat build.log && exit 1)

# If we get here, build succeeded
RUN npm install -g serve
EXPOSE 3000
CMD ["serve", "-s", "build", "-l", "3000"]