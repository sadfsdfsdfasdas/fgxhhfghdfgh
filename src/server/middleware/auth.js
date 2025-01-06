  
import crypto from 'crypto';

// In a real application, you'd want to store this securely,
// preferably in environment variables
const ADMIN_CREDENTIALS = {
    username: 'admin',
    password: '123', // Store hashed password in production
    token: '123'
};

// Verify admin token
export function verifyAdmin(token) {
    return token === ADMIN_CREDENTIALS.token;
}

// Generate session token
export function generateToken(username, password) {
    if (username === ADMIN_CREDENTIALS.username && password === ADMIN_CREDENTIALS.password) {
        return ADMIN_CREDENTIALS.token;
    }
    return null;
}

// Hash function for passwords (use in production)
export function hashPassword(password) {
    return crypto
        .createHash('sha256')
        .update(password)
        .digest('hex');
}