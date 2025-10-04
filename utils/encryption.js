const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Validate critical environment variables
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('CRITICAL: JWT_SECRET must be set and at least 32 characters long!');
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
}

if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length < 64) {
    console.error('CRITICAL: ENCRYPTION_KEY must be set and at least 64 characters long!');
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Encryption configuration
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY
    ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex').slice(0, 32)
    : null;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

class EncryptionUtils {
    // Password hashing with enhanced validation
    static async hashPassword(password) {
        if (!password || typeof password !== 'string') {
            throw new Error('Password must be a string');
        }

        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters long');
        }

        if (password.length > 128) {
            throw new Error('Password is too long (maximum 128 characters)');
        }

        // Strong password requirements
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!strongPasswordRegex.test(password)) {
            throw new Error('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)');
        }

        // Check for common weak passwords
        const weakPasswords = [
            'password', 'password123', '12345678', 'qwerty123',
            'admin123', 'letmein', 'welcome123', 'password1'
        ];

        if (weakPasswords.includes(password.toLowerCase())) {
            throw new Error('This password is too common. Please choose a stronger password');
        }

        return await bcrypt.hash(password, 12);
    }

    static async verifyPassword(password, hash) {
        if (!password || !hash) {
            return false;
        }

        try {
            return await bcrypt.compare(password, hash);
        } catch (error) {
            console.error('Password verification error:', error);
            return false;
        }
    }

    // Enhanced JWT token generation with session tracking
    static generateToken(payload) {
        if (!payload.userId) {
            throw new Error('userId is required in token payload');
        }

        // Add additional security claims
        const tokenPayload = {
            ...payload,
            iat: Math.floor(Date.now() / 1000),
            jti: crypto.randomBytes(16).toString('hex'), // JWT ID for tracking
        };

        return jwt.sign(tokenPayload, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN,
            issuer: 'imips-backend',
            audience: 'imips-client'
        });
    }

    static verifyToken(token) {
        try {
            return jwt.verify(token, JWT_SECRET, {
                issuer: 'imips-backend',
                audience: 'imips-client'
            });
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                const expiredError = new Error('Token has expired');
                expiredError.name = 'TokenExpiredError';
                throw expiredError;
            }
            throw new Error('Invalid or expired token');
        }
    }

    // Secure data encryption using AES-256-GCM
    static encryptText(text) {
        if (!ENCRYPTION_KEY) {
            throw new Error('ENCRYPTION_KEY not configured');
        }

        if (typeof text !== 'string') {
            throw new Error('Input must be a string');
        }

        if (text.length > 1000000) {
            throw new Error('Input text too large for encryption');
        }

        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Combine IV + authTag + encrypted data
        return iv.toString('hex') + authTag.toString('hex') + encrypted;
    }

    static decryptText(encryptedText) {
        if (!ENCRYPTION_KEY) {
            throw new Error('ENCRYPTION_KEY not configured');
        }

        if (typeof encryptedText !== 'string') {
            throw new Error('Input must be a string');
        }

        try {
            // Extract components
            const iv = Buffer.from(encryptedText.substring(0, IV_LENGTH * 2), 'hex');
            const authTag = Buffer.from(
                encryptedText.substring(IV_LENGTH * 2, (IV_LENGTH + AUTH_TAG_LENGTH) * 2),
                'hex'
            );
            const encryptedData = encryptedText.substring((IV_LENGTH + AUTH_TAG_LENGTH) * 2);

            const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error('Decryption failed - data may be corrupted or tampered');
        }
    }

    // Encrypt file with streaming support
    static encryptFile(inputPath, outputPath) {
        return new Promise((resolve, reject) => {
            if (!ENCRYPTION_KEY) {
                return reject(new Error('ENCRYPTION_KEY not configured'));
            }

            const fs = require('fs');
            const iv = crypto.randomBytes(IV_LENGTH);
            const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);

            const input = fs.createReadStream(inputPath);
            const output = fs.createWriteStream(outputPath);

            // Write IV first
            output.write(iv);

            input.pipe(cipher).pipe(output);

            output.on('finish', () => {
                const authTag = cipher.getAuthTag();
                // Append auth tag
                fs.appendFile(outputPath, authTag, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });

            output.on('error', reject);
            input.on('error', reject);
        });
    }

    // Utility method to generate secure encryption keys
    static generateEncryptionKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    static generateJWTSecret() {
        return crypto.randomBytes(64).toString('hex');
    }

    // Method to create key from password (for key derivation)
    static async deriveKeyFromPassword(password, saltHex = null) {
        const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);

        return new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, 32, (err, derivedKey) => {
                if (err) reject(err);
                else resolve({
                    key: derivedKey.toString('hex'),
                    salt: salt.toString('hex')
                });
            });
        });
    }

    // Generate secure random tokens for password reset, etc.
    static generateSecureToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Hash data using SHA-256 (for integrity checks)
    static hashData(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    // Constant-time comparison to prevent timing attacks
    static constantTimeCompare(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string') {
            return false;
        }

        if (a.length !== b.length) {
            return false;
        }

        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

    // Validate and sanitize sensitive data
    static sanitizeSensitiveData(data) {
        // Remove common sensitive patterns
        return data
            .replace(/password/gi, '[REDACTED]')
            .replace(/token/gi, '[REDACTED]')
            .replace(/secret/gi, '[REDACTED]')
            .replace(/apikey/gi, '[REDACTED]');
    }
}

module.exports = EncryptionUtils;