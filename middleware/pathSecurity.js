const { logSecurityEvent } = require('./security');

// Track suspicious activity per IP
const suspiciousActivity = new Map();
const SUSPICIOUS_THRESHOLD = 20; // Max 20 suspicious requests
const BLOCK_DURATION = 60 * 60 * 1000; // 1 hour
const WINDOW_DURATION = 5 * 60 * 1000; // 5 minutes

// Blocked IPs
const blockedIPs = new Map();

/**
 * Path enumeration detection and prevention middleware
 * Blocks IPs that make too many requests to non-existent endpoints
 */
const preventPathEnumeration = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;

    // Check if IP is blocked
    if (isIPBlocked(ip)) {
        logSecurityEvent('BLOCKED_IP_ATTEMPT', req, { ip });
        return res.status(403).json({
            message: 'Access forbidden'
        });
    }

    // Store original res.status to intercept 404s
    const originalStatus = res.status.bind(res);
    res.status = function (code) {
        if (code === 404) {
            trackSuspiciousActivity(ip, req);
        }
        return originalStatus(code);
    };

    next();
};

/**
 * Check if IP is currently blocked
 */
function isIPBlocked(ip) {
    const blockInfo = blockedIPs.get(ip);

    if (!blockInfo) {
        return false;
    }

    // Check if block has expired
    if (Date.now() > blockInfo.expiresAt) {
        blockedIPs.delete(ip);
        return false;
    }

    return true;
}

/**
 * Track 404 errors and block IPs with excessive requests
 */
function trackSuspiciousActivity(ip, req) {
    let activity = suspiciousActivity.get(ip);
    const now = Date.now();

    if (!activity) {
        activity = {
            count: 0,
            firstRequest: now,
            paths: []
        };
        suspiciousActivity.set(ip, activity);
    }

    // Reset counter if outside window
    if (now - activity.firstRequest > WINDOW_DURATION) {
        activity.count = 0;
        activity.firstRequest = now;
        activity.paths = [];
    }

    // Track the path
    activity.count++;
    activity.paths.push({
        path: req.originalUrl,
        timestamp: now,
        method: req.method
    });

    // Block if threshold exceeded
    if (activity.count >= SUSPICIOUS_THRESHOLD) {
        blockIP(ip, activity.paths);
        suspiciousActivity.delete(ip);

        logSecurityEvent('IP_BLOCKED_PATH_ENUMERATION', req, {
            ip,
            attemptCount: activity.count,
            paths: activity.paths.slice(-5) // Last 5 paths
        });
    }
}

/**
 * Block an IP address
 */
function blockIP(ip, paths) {
    blockedIPs.set(ip, {
        blockedAt: Date.now(),
        expiresAt: Date.now() + BLOCK_DURATION,
        reason: 'Path enumeration detected',
        paths
    });

    console.warn(`⚠ IP blocked for path enumeration: ${ip}`);
}

/**
 * Unblock an IP manually (admin function)
 */
function unblockIP(ip) {
    blockedIPs.delete(ip);
    suspiciousActivity.delete(ip);
    console.log(`IP unblocked: ${ip}`);
}

/**
 * Get list of blocked IPs
 */
function getBlockedIPs() {
    const blocked = [];
    const now = Date.now();

    for (const [ip, info] of blockedIPs.entries()) {
        if (now > info.expiresAt) {
            blockedIPs.delete(ip);
        } else {
            blocked.push({
                ip,
                blockedAt: new Date(info.blockedAt).toISOString(),
                expiresAt: new Date(info.expiresAt).toISOString(),
                reason: info.reason,
                pathsAttempted: info.paths.length
            });
        }
    }

    return blocked;
}

/**
 * Custom 404 handler that prevents information disclosure
 */
const handle404 = (req, res) => {
    // Don't reveal if path exists or not - return generic message
    const ip = req.ip || req.connection.remoteAddress;

    logSecurityEvent('404_NOT_FOUND', req, {
        ip,
        path: req.originalUrl,
        method: req.method
    });

    // Generic response - don't hint at valid paths
    res.status(404).json({
        message: 'Resource not found'
    });
};

/**
 * Handle API 404s specifically
 */
const handleAPI404 = (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;

    logSecurityEvent('API_404_NOT_FOUND', req, {
        ip,
        path: req.originalUrl,
        method: req.method,
        userAgent: req.headers['user-agent']
    });

    // Generic response
    res.status(404).json({
        message: 'API endpoint not found'
    });
};

/**
 * Whitelist certain IPs from blocking (internal services, load balancers)
 */
const whitelistedIPs = new Set(
    (process.env.WHITELISTED_IPS || '').split(',').filter(ip => ip.trim())
);

function isWhitelisted(ip) {
    return whitelistedIPs.has(ip);
}

/**
 * Advanced path enumeration detection
 * Detects common scanning patterns
 */
const detectScanningPatterns = (req, res, next) => {
    const suspiciousPatterns = [
        // Common vulnerability scanners
        /\.(env|git|svn|DS_Store)/i,
        /\/(admin|phpmyadmin|wp-admin|config|backup)/i,
        /\.(sql|bak|backup|old|zip|tar\.gz)$/i,

        // Path traversal attempts
        /\.\.[\/\\]/,

        // Common attack paths
        /\/(etc\/passwd|proc\/self|windows\/system)/i,

        // Scanner signatures in path
        /\/(test|temp|tmp|debug|dev|staging)/i,

        // SQL injection attempts in URL
        /(union|select|insert|update|delete|drop|create|alter)\s/i,

        // Command injection
        /[;&|`$(){}[\]]/,

        // XSS attempts in URL
        /(<script|javascript:|onerror=|onload=)/i
    ];

    const path = req.originalUrl.toLowerCase();
    const ip = req.ip || req.connection.remoteAddress;

    // Check for suspicious patterns
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(path)) {
            logSecurityEvent('SUSPICIOUS_PATH_DETECTED', req, {
                ip,
                path: req.originalUrl,
                pattern: pattern.toString()
            });

            // Immediate block for obvious attack attempts
            if (pattern.test(path) && !isWhitelisted(ip)) {
                blockIP(ip, [{
                    path: req.originalUrl,
                    timestamp: Date.now(),
                    method: req.method,
                    reason: 'Malicious pattern detected'
                }]);

                return res.status(403).json({
                    message: 'Access forbidden'
                });
            }
        }
    }

    next();
};

/**
 * Detect automated scanning tools by User-Agent
 */
const detectScannerUserAgents = (req, res, next) => {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const ip = req.ip || req.connection.remoteAddress;

    const scannerSignatures = [
        'nmap', 'nikto', 'sqlmap', 'metasploit', 'burp',
        'acunetix', 'nessus', 'openvas', 'qualys', 'w3af',
        'masscan', 'zap', 'arachni', 'skipfish', 'wfuzz',
        'dirbuster', 'gobuster', 'ffuf', 'wpscan'
    ];

    for (const scanner of scannerSignatures) {
        if (userAgent.includes(scanner)) {
            logSecurityEvent('SCANNER_DETECTED', req, {
                ip,
                userAgent: req.headers['user-agent'],
                scanner
            });

            if (!isWhitelisted(ip)) {
                blockIP(ip, [{
                    path: req.originalUrl,
                    timestamp: Date.now(),
                    method: req.method,
                    reason: `Scanner detected: ${scanner}`
                }]);

                return res.status(403).json({
                    message: 'Access forbidden'
                });
            }
        }
    }

    next();
};

/**
 * Rate limit 404 responses per IP
 */
const notFoundRateLimiter = {};
const MAX_404_PER_MINUTE = 20;

function check404RateLimit(ip) {
    const now = Date.now();
    const minute = Math.floor(now / 60000);

    if (!notFoundRateLimiter[ip]) {
        notFoundRateLimiter[ip] = {};
    }

    // Clean old entries
    for (const key in notFoundRateLimiter[ip]) {
        if (parseInt(key) < minute - 5) {
            delete notFoundRateLimiter[ip][key];
        }
    }

    notFoundRateLimiter[ip][minute] = (notFoundRateLimiter[ip][minute] || 0) + 1;

    return notFoundRateLimiter[ip][minute] <= MAX_404_PER_MINUTE;
}

/**
 * Method-based restrictions
 */
const restrictMethods = (req, res, next) => {
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

    if (!allowedMethods.includes(req.method)) {
        logSecurityEvent('INVALID_HTTP_METHOD', req, {
            method: req.method
        });

        return res.status(405).json({
            message: 'Method not allowed'
        });
    }

    next();
};

// Cleanup expired blocks periodically
setInterval(() => {
    const now = Date.now();

    // Clean blocked IPs
    for (const [ip, info] of blockedIPs.entries()) {
        if (now > info.expiresAt) {
            blockedIPs.delete(ip);
            console.log(`IP unblocked (expired): ${ip}`);
        }
    }

    // Clean suspicious activity older than window
    for (const [ip, activity] of suspiciousActivity.entries()) {
        if (now - activity.firstRequest > WINDOW_DURATION) {
            suspiciousActivity.delete(ip);
        }
    }
}, 60000); // Every minute

module.exports = {
    preventPathEnumeration,
    detectScanningPatterns,
    detectScannerUserAgents,
    restrictMethods,
    handle404,
    handleAPI404,
    isIPBlocked,
    blockIP,
    unblockIP,
    getBlockedIPs,
    check404RateLimit
};