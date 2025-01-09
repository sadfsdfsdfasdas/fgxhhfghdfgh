# Start with php-fpm base image
FROM php:8.1-fpm

# Install Node.js LTS
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get update && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Verify installations
RUN php -v && \
    php -m && \
    node -v && \
    npm -v

# Install any additional PHP extensions you need
RUN docker-php-ext-install pdo pdo_mysql

# Create PHP log directory
RUN mkdir -p /var/log/php && \
    touch /var/log/php/error.log && \
    chmod 777 /var/log/php/error.log

# Set working directory
WORKDIR /app

# Create the public directory
RUN mkdir -p public

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy application files
COPY . .

# Create a test PHP file and verify it works
RUN echo "<?php phpinfo(); ?>" > test.php && \
    php test.php && \
    rm test.php

# Expose port
EXPOSE 3000

# Start command
CMD ["node", "src/server/index.js"]
