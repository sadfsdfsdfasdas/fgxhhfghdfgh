FROM node:18

# Install PHP and required extensions
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y php8.1 \
        php8.1-cli \
        php8.1-common \
        php8.1-curl \
        php8.1-mbstring \
        php8.1-xml \
        && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /var/log/php && \
    touch /var/log/php/error.log && \
    chmod 777 /var/log/php/error.log

# Verify PHP installation
RUN php -v && \
    php -m && \
    which php

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

# Final verification
RUN echo "<?php echo 'PHP Test Successful'; ?>" > test.php && \
    php test.php && \
    rm test.php

# Expose port
EXPOSE 3000

# Start command
CMD ["node", "src/server/index.js"]
