# Use PHP as base image
FROM php:8.1-cli

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get update && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Verify installations
RUN php -v && \
    node -v && \
    npm -v

# Create log directory
RUN mkdir -p /var/log/php && \
    touch /var/log/php/error.log && \
    chmod 777 /var/log/php/error.log

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application
COPY . .

# Build the application
RUN npm run build

# Create a test PHP file and verify it works
RUN echo "<?php echo 'PHP Test'; ?>" > test.php && \
    php test.php && \
    rm test.php

# Expose port
EXPOSE 3000

# Start command
CMD ["node", "src/server/index.js"]
