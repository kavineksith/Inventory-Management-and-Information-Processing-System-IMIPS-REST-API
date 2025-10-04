const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const mime = require('mime-types');
const fileType = require('file-type');
const { executeQuery } = require('../config/database');

// Failed login attempts tracking (in-memory, consider Redis for production)
const loginAttempts = new Map();
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const MAX_LOGIN_ATTEMPTS = 5;

// Security middleware configuration
const securityMiddleware = (app) => {
    // Force HTTPS in production
    if (process.env.NODE_ENV === 'production') {
        app.use((req, res, next) => {
            if (req.headers['x-forwarded-proto'] !== 'https') {
                return res.redirect(301, `https://${req.headers.host}${req.url}`);
            }
            next();
        });
    }

    // Enhanced Helmet configuration
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "blob:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: true,
        crossOriginResourcePolicy: { policy: "same-site" },
        dnsPrefetchControl: true,
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        },
        ieNoOpen: true,
        noSniff: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        xssFilter: true,
    }));

    // CORS configuration with strict validation
    app.use((req, res, next) => {
        const allowedOrigins = process.env.ALLOWED_ORIGINS
            ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
            : [];

        const origin = req.headers.origin;

        if (allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }

        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

        if (req.method === 'OPTIONS') {
            return res.sendStatus(204);
        }

        next();
    });

    // Enhanced rate limiting with different tiers
    const authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 5,
        skipSuccessfulRequests: false,
        message: { message: 'Too many login attempts. Please try again later.' },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            logSecurityEvent('RATE_LIMIT_AUTH', req);
            res.status(429).json({
                message: 'Too many login attempts. Please try again after 15 minutes.'
            });
        }
    });

    const generalLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 100,
        message: { message: 'Too many requests. Please try again later.' },
        standardHeaders: true,
        legacyHeaders: false,
    });

    const strictLimiter = rateLimit({
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 10,
        message: { message: 'Too many sensitive operations. Please try again later.' },
        standardHeaders: true,
        legacyHeaders: false,
    });

    app.use('/api/auth/login', authLimiter);
    app.use('/api/auth/register', authLimiter);
    app.use('/api/backup/restore', strictLimiter);
    app.use('/api/backup/create', strictLimiter);
    app.use('/api/', generalLimiter);

    // Request size limits
    app.use((req, res, next) => {
        const contentLength = parseInt(req.headers['content-length'] || '0');
        const maxSize = 10 * 1024 * 1024; // 10MB

        if (contentLength > maxSize) {
            return res.status(413).json({ message: 'Request entity too large' });
        }
        next();
    });
};

// Account lockout mechanism
const checkAccountLockout = (identifier) => {
    const attempts = loginAttempts.get(identifier);

    if (!attempts) {
        return { locked: false, remainingAttempts: MAX_LOGIN_ATTEMPTS };
    }

    const { count, lockedUntil } = attempts;

    // Check if account is locked
    if (lockedUntil && Date.now() < lockedUntil) {
        const minutesRemaining = Math.ceil((lockedUntil - Date.now()) / 60000);
        return {
            locked: true,
            message: `Account locked. Try again in ${minutesRemaining} minutes.`,
            remainingAttempts: 0
        };
    }

    // Reset if lockout period expired
    if (lockedUntil && Date.now() >= lockedUntil) {
        loginAttempts.delete(identifier);
        return { locked: false, remainingAttempts: MAX_LOGIN_ATTEMPTS };
    }

    return {
        locked: false,
        remainingAttempts: MAX_LOGIN_ATTEMPTS - count
    };
};

const recordFailedLogin = (identifier) => {
    const attempts = loginAttempts.get(identifier) || { count: 0 };
    attempts.count += 1;

    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        attempts.lockedUntil = Date.now() + LOCKOUT_DURATION;
    }

    loginAttempts.set(identifier, attempts);
    return attempts;
};

const clearLoginAttempts = (identifier) => {
    loginAttempts.delete(identifier);
};

// Enhanced file upload security with magic number validation
const fileUploadSecurity = async (req, res, next) => {
    if (!req.file) {
        return next();
    }

    try {
        // Validate file type by reading file content (magic numbers)
        const fileBuffer = await require('fs-extra').readFile(req.file.path);
        const detectedType = await fileType.fromBuffer(fileBuffer);

        const allowedTypes = {
            'image/jpeg': ['jpg', 'jpeg'],
            'image/png': ['png'],
            'image/gif': ['gif'],
            'application/pdf': ['pdf']
        };

        // Validate detected MIME type
        if (!detectedType || !allowedTypes[detectedType.mime]) {
            await require('fs-extra').unlink(req.file.path);
            return res.status(400).json({
                message: 'Invalid file type detected. Only JPEG, PNG, GIF, and PDF files are allowed.'
            });
        }

        // Check file size
        if (req.file.size > 5 * 1024 * 1024) {
            await require('fs-extra').unlink(req.file.path);
            return res.status(400).json({
                message: 'File size too large. Maximum size is 5MB.'
            });
        }

        // Sanitize filename
        const sanitizedFilename = req.file.originalname
            .replace(/[^a-zA-Z0-9.\-_]/g, '_')
            .substring(0, 255);

        req.file.sanitizedFilename = sanitizedFilename;
        req.file.detectedMimeType = detectedType.mime;

        next();
    } catch (error) {
        console.error('File validation error:', error);
        try {
            await require('fs-extra').unlink(req.file.path);
        } catch (unlinkError) {
            console.error('Failed to delete invalid file:', unlinkError);
        }
        return res.status(400).json({ message: 'File validation failed' });
    }
};

// Path traversal protection
const preventPathTraversal = (req, res, next) => {
    const userInput = { ...req.params, ...req.query, ...req.body };

    const hasPathTraversal = Object.values(userInput).some(value => {
        if (typeof value === 'string') {
            const dangerous = [
                '../', '..\\',
                '/etc/passwd', '/etc/shadow',
                'c:\\windows', 'c:/windows',
                '%2e%2e/', '%2e%2e%5c'
            ];
            return dangerous.some(pattern =>
                value.toLowerCase().includes(pattern.toLowerCase())
            );
        }
        return false;
    });

    if (hasPathTraversal) {
        logSecurityEvent('PATH_TRAVERSAL_ATTEMPT', req);
        return res.status(400).json({ message: 'Invalid request parameters' });
    }

    next();
};

// Enhanced XSS Protection using DOMPurify-like approach
const xssProtection = (req, res, next) => {
    const sanitize = (obj) => {
        for (let key in obj) {
            if (typeof obj[key] === 'string') {
                // More comprehensive XSS protection
                obj[key] = obj[key]
                    .replace(/[<>]/g, '') // Remove angle brackets
                    .replace(/javascript:/gi, '')
                    .replace(/on\w+\s*=/gi, '') // Remove event handlers
                    .replace(/&lt;/g, '')
                    .replace(/&gt;/g, '')
                    .substring(0, 10000); // Limit length
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitize(obj[key]);
            }
        }
    };

    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    if (req.params) sanitize(req.params);

    next();
};

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

// Security event logging
async function logSecurityEvent(eventType, req, additionalData = {}) {
    try {
        const logEntry = {
            timestamp: new Date().toISOString(),
            eventType,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            url: req.originalUrl,
            method: req.method,
            userId: req.user?.id || null,
            ...additionalData
        };

        console.warn('SECURITY EVENT:', JSON.stringify(logEntry));

        // Optionally store in database
        if (process.env.LOG_SECURITY_TO_DB === 'true') {
            await executeQuery(
                `INSERT INTO security_logs (event_type, ip_address, user_agent, url, user_id, details, created_at) 
                 VALUES (?, ?, ?, ?, ?, ?, NOW())`,
                [eventType, logEntry.ip, logEntry.userAgent, logEntry.url, logEntry.userId, JSON.stringify(additionalData)]
            ).catch(err => console.error('Failed to log security event to DB:', err));
        }
    } catch (error) {
        console.error('Failed to log security event:', error);
    }
}

// Audit logging middleware for sensitive operations
const auditLog = (action) => {
    return async (req, res, next) => {
        const originalJson = res.json;

        res.json = function (data) {
            // Log after successful response
            if (res.statusCode < 400) {
                logSecurityEvent('AUDIT_LOG', req, {
                    action,
                    success: true,
                    targetId: req.params.id || null
                });
            }
            originalJson.call(this, data);
        };

        next();
    };
};

module.exports = {
    securityMiddleware,
    fileUploadSecurity,
    preventPathTraversal,
    xssProtection,
    csrfProtection,
    checkAccountLockout,
    recordFailedLogin,
    clearLoginAttempts,
    logSecurityEvent,
    auditLog
};