const EncryptionUtils = require('../utils/encryption');
const { executeQuery } = require('../config/database');
const { logSecurityEvent } = require('./security');

// Active sessions tracking (consider Redis for production)
const activeSessions = new Map();

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = EncryptionUtils.verifyToken(token);

        // Check if session is valid
        const sessionValid = await verifySession(decoded.userId, decoded.sessionId);
        if (!sessionValid) {
            return res.status(401).json({ message: 'Session expired or invalid' });
        }

        // Verify user still exists and is not deleted
        const user = await executeQuery(
            'SELECT id, name, email, role, profile_picture_url, is_deleted, password_changed_at FROM users WHERE id = ? AND is_deleted = false',
            [decoded.userId]
        );

        if (user.length === 0) {
            await invalidateUserSessions(decoded.userId);
            return res.status(401).json({ message: 'User not found or deactivated' });
        }

        // Check if password was changed after token was issued
        if (user[0].password_changed_at) {
            const tokenIssuedAt = new Date(decoded.iat * 1000);
            const passwordChangedAt = new Date(user[0].password_changed_at);

            if (passwordChangedAt > tokenIssuedAt) {
                await invalidateUserSessions(decoded.userId);
                return res.status(401).json({
                    message: 'Password was changed. Please login again.'
                });
            }
        }

        req.user = user[0];
        req.sessionId = decoded.sessionId;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired. Please login again.' });
        }
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
};

const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        if (!roles.includes(req.user.role)) {
            logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', req, {
                requiredRoles: roles,
                userRole: req.user.role
            });
            return res.status(403).json({ message: 'Insufficient permissions' });
        }

        next();
    };
};

// Role hierarchy check
const canModifyUser = (req, res, next) => {
    const targetUserId = req.params.id;

    // Users can modify their own profile, admins can modify anyone
    if (req.user.id === targetUserId || req.user.role === 'Admin') {
        return next();
    }

    logSecurityEvent('UNAUTHORIZED_USER_MODIFICATION_ATTEMPT', req, {
        targetUserId
    });

    return res.status(403).json({ message: 'Insufficient permissions to modify this user' });
};

// Activity tracking middleware with session validation
const trackActivity = async (req, res, next) => {
    if (req.user) {
        try {
            await executeQuery(
                'UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = ?',
                [req.user.id]
            );

            // Update session last activity
            await executeQuery(
                'UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?',
                [req.sessionId]
            );
        } catch (error) {
            console.error('Activity tracking error:', error);
        }
    }
    next();
};

// Session management functions
async function createSession(userId, ipAddress, userAgent) {
    const sessionId = require('uuid').v4();

    try {
        await executeQuery(
            `INSERT INTO user_sessions 
             (id, user_id, ip_address, user_agent, login_time, last_activity) 
             VALUES (?, ?, ?, ?, NOW(), NOW())`,
            [sessionId, userId, ipAddress, userAgent]
        );

        activeSessions.set(sessionId, {
            userId,
            createdAt: Date.now()
        });

        // Limit concurrent sessions per user
        await limitConcurrentSessions(userId);

        return sessionId;
    } catch (error) {
        console.error('Session creation error:', error);
        throw new Error('Failed to create session');
    }
}

async function verifySession(userId, sessionId) {
    // Check in-memory cache first
    const cachedSession = activeSessions.get(sessionId);
    if (cachedSession && cachedSession.userId === userId) {
        return true;
    }

    // Verify in database
    try {
        const sessions = await executeQuery(
            `SELECT id FROM user_sessions 
             WHERE id = ? AND user_id = ? AND logout_time IS NULL`,
            [sessionId, userId]
        );

        if (sessions.length > 0) {
            activeSessions.set(sessionId, { userId, createdAt: Date.now() });
            return true;
        }
    } catch (error) {
        console.error('Session verification error:', error);
    }

    return false;
}

async function invalidateSession(sessionId) {
    activeSessions.delete(sessionId);

    try {
        await executeQuery(
            `UPDATE user_sessions 
             SET logout_time = NOW(), 
                 duration_minutes = TIMESTAMPDIFF(MINUTE, login_time, NOW()) 
             WHERE id = ? AND logout_time IS NULL`,
            [sessionId]
        );
    } catch (error) {
        console.error('Session invalidation error:', error);
    }
}

async function invalidateUserSessions(userId) {
    // Remove from cache
    for (const [sessionId, data] of activeSessions.entries()) {
        if (data.userId === userId) {
            activeSessions.delete(sessionId);
        }
    }

    // Invalidate in database
    try {
        await executeQuery(
            `UPDATE user_sessions 
             SET logout_time = NOW(), 
                 duration_minutes = TIMESTAMPDIFF(MINUTE, login_time, NOW()) 
             WHERE user_id = ? AND logout_time IS NULL`,
            [userId]
        );
    } catch (error) {
        console.error('User sessions invalidation error:', error);
    }
}

async function limitConcurrentSessions(userId, maxSessions = 5) {
    try {
        const sessions = await executeQuery(
            `SELECT id FROM user_sessions 
             WHERE user_id = ? AND logout_time IS NULL 
             ORDER BY login_time DESC`,
            [userId]
        );

        if (sessions.length > maxSessions) {
            const sessionsToRemove = sessions.slice(maxSessions);
            for (const session of sessionsToRemove) {
                await invalidateSession(session.id);
            }
        }
    } catch (error) {
        console.error('Concurrent session limit error:', error);
    }
}

// Cleanup expired sessions periodically
setInterval(async () => {
    try {
        // Clean up sessions older than 24 hours with no activity
        await executeQuery(
            `UPDATE user_sessions 
             SET logout_time = NOW(), 
                 duration_minutes = TIMESTAMPDIFF(MINUTE, login_time, NOW()) 
             WHERE logout_time IS NULL 
             AND last_activity < DATE_SUB(NOW(), INTERVAL 24 HOUR)`
        );

        // Clear expired sessions from memory
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        for (const [sessionId, data] of activeSessions.entries()) {
            if (now - data.createdAt > maxAge) {
                activeSessions.delete(sessionId);
            }
        }
    } catch (error) {
        console.error('Session cleanup error:', error);
    }
}, 60 * 60 * 1000); // Run every hour

module.exports = {
    authenticateToken,
    requireRole,
    canModifyUser,
    trackActivity,
    createSession,
    verifySession,
    invalidateSession,
    invalidateUserSessions
};