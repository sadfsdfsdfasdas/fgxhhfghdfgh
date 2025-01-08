FROM node:18

# Add Sury PHP repository
RUN apt-get update && \
    apt-get install -y lsb-release ca-certificates apt-transport-https software-properties-common gnupg2 && \
    echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/sury-php.list && \
    curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/sury-keyring.gpg

# Install PHP 8.1
RUN apt-get update && \
    apt-get install -y \
    php8.1 \
    php8.1-cli \
    php8.1-common \
    php8.1-curl \
    php8.1-mbstring \
    php8.1-xml \
    && rm -rf /var/lib/apt/lists/*

# Verify PHP installation and create symbolic link
RUN php -v && \
    which php && \
    ln -sf /usr/bin/php8.1 /usr/bin/php && \
    chmod +x /usr/bin/php

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

# Verify PHP is accessible from the application directory
RUN php -v && \
    ls -la /usr/bin/php* && \
    echo "PHP installation verified"

# Expose port
EXPOSE 3000

# Start command
CMD ["node", "src/server/index.js"]
