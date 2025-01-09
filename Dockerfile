# Use PHP Apache image as base
FROM php:8.1-apache

# Install dependencies for Node.js
RUN apt-get update && \
    apt-get install -y curl gnupg && \
    curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get update && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy application files
COPY . .

# Set up logging directory
RUN mkdir -p /var/log/php && \
    chown -R www-data:www-data /var/log/php && \
    chmod 755 /var/log/php

# Verify installations
RUN echo "PHP version:" && php -v && \
    echo "\nNode version:" && node -v && \
    echo "\nNPM version:" && npm -v && \
    echo "\nPHP test:" && php -r "echo 'PHP is working';" && \
    php -m

# Expose port
EXPOSE 3000

# Set PHP path in environment
ENV PATH="/usr/local/bin/php:${PATH}"

# Start command
CMD ["node", "src/server/index.js"]
