const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const EncryptionUtils = require('../utils/encryption');
const { executeQuery } = require('../config/database');
const { 
    authenticateToken, 
    trackActivity,
    createSession,
    invalidateSession,
    invalidateUserSessions
} = require('../middleware/auth');
const { validateLogin, validateRegister } = require('../middleware/validation');
const { 
    checkAccountLockout, 
    recordFailedLogin, 
    clearLoginAttempts,
    logSecurityEvent,
    csrfProtection 
} = require('../middleware/security');

// Get CSRF token
router.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Login with enhanced security
router.post('/login', validateLogin, async (req, res) => {
    try {
        const { email, password } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        // Check account lockout
        const lockoutStatus = checkAccountLockout(email);
        if (lockoutStatus.locked) {
            logSecurityEvent('LOGIN_ATTEMPT_LOCKED_ACCOUNT', req, { email });
            return res.status(429).json({ 
                message: lockoutStatus.message 
            });
        }

        const users = await executeQuery(
            'SELECT id, name, email, password_hash, role, profile_picture_url, is_deleted FROM users WHERE email = ? AND is_deleted = false',
            [email]
        );

        if (users.length === 0) {
            recordFailedLogin(email);
            logSecurityEvent('LOGIN_FAILED_USER_NOT_FOUND', req, { email });
            return res.status(401).json({ 
                message: 'Invalid email or password',
                remainingAttempts: lockoutStatus.remainingAttempts - 1
            });
        }

        const user = users[0];
        const isValidPassword = await EncryptionUtils.verifyPassword(password, user.password_hash);

        if (!isValidPassword) {
            const attempts = recordFailedLogin(email);
            logSecurityEvent('LOGIN_FAILED_INVALID_PASSWORD', req, { 
                email,
                attemptsCount: attempts.count 
            });
            
            return res.status(401).json({ 
                message: 'Invalid email or password',
                remainingAttempts: Math.max(0, lockoutStatus.remainingAttempts - attempts.count)
            });
        }

        // Clear failed login attempts on successful login
        clearLoginAttempts(email);

        // Create session with tracking
        const sessionId = await createSession(user.id, ipAddress, userAgent);

        // Update last activity
        await executeQuery(
            'UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = ?',
            [user.id]
        );

        // Generate token with session ID
        const token = EncryptionUtils.generateToken({ 
            userId: user.id, 
            role: user.role,
            sessionId
        });

        logSecurityEvent('LOGIN_SUCCESS', req, { 
            userId: user.id,
            sessionId 
        });

        res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                profilePictureUrl: user.profile_picture_url
            },
            accessToken: token
        });
    } catch (error) {
        console.error('Login error:', error);
        logSecurityEvent('LOGIN_ERROR', req, { error: error.message });
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Register (Admin only) with enhanced validation
router.post('/register', authenticateToken, validateRegister, async (req, res) => {
    try {
        if (req.user.role !== 'Admin') {
            logSecurityEvent('UNAUTHORIZED_REGISTRATION_ATTEMPT', req);
            return res.status(403).json({ 
                message: 'Only administrators can register new users' 
            });
        }

        const { name, email, password, role } = req.body;
        const userId = uuidv4();
        const passwordHash = await EncryptionUtils.hashPassword(password);

        await executeQuery(
            'INSERT INTO users (id, name, email, password_hash, role, password_changed_at) VALUES (?, ?, ?, ?, ?, NOW())',
            [userId, name, email, passwordHash, role]
        );

        const newUser = await executeQuery(
            'SELECT id, name, email, role, profile_picture_url, is_deleted FROM users WHERE id = ?',
            [userId]
        );

        logSecurityEvent('USER_REGISTERED', req, { 
            newUserId: userId,
            newUserRole: role 
        });

        // Send welcome email with credentials
        try {
            const emailService = require('../utils/emailService');
            await emailService.sendWelcomeEmail(email, name, password);
            console.log('Welcome email sent to:', email);
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError);
            // Continue even if email fails
        }

        res.status(201).json({ 
            user: newUser[0],
            message: 'User created successfully. Welcome email has been sent.'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get current user
router.get('/me', authenticateToken, trackActivity, async (req, res) => {
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        profilePictureUrl: req.user.profile_picture_url
    });
});

// Logout with session cleanup
router.post('/logout', authenticateToken, async (req, res) => {
    try {
        await invalidateSession(req.sessionId);

        logSecurityEvent('LOGOUT_SUCCESS', req);
        res.json({ message: 'Logout successful' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Logout from all devices
router.post('/logout-all', authenticateToken, async (req, res) => {
    try {
        await invalidateUserSessions(req.user.id);

        logSecurityEvent('LOGOUT_ALL_SESSIONS', req);
        res.json({ message: 'Logged out from all devices successfully' });
    } catch (error) {
        console.error('Logout all error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Password reset request (generates secure token)
router.post('/password-reset-request', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        const users = await executeQuery(
            'SELECT id, name, email FROM users WHERE email = ? AND is_deleted = false',
            [email]
        );

        // Always return success to prevent email enumeration
        if (users.length > 0) {
            const resetToken = EncryptionUtils.generateSecureToken();
            const resetExpiry = new Date(Date.now() + 3600000); // 1 hour

            // Store reset token
            await executeQuery(
                `INSERT INTO password_resets (user_id, token, expires_at) 
                 VALUES (?, ?, ?) 
                 ON DUPLICATE KEY UPDATE token = ?, expires_at = ?`,
                [users[0].id, resetToken, resetExpiry, resetToken, resetExpiry]
            );

            logSecurityEvent('PASSWORD_RESET_REQUESTED', req, { 
                userId: users[0].id 
            });

            // Send password reset email
            try {
                const emailService = require('../utils/emailService');
                await emailService.sendPasswordResetEmail(
                    users[0].email,
                    users[0].name,
                    resetToken
                );
                console.log('Password reset email sent to:', users[0].email);
            } catch (emailError) {
                console.error('Failed to send password reset email:', emailError);
                // Don't reveal email sending failure to user for security
            }
        }

        res.json({ 
            message: 'If an account with that email exists, a password reset link has been sent' 
        });
    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Verify password reset token
router.post('/password-reset-verify', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: 'Token is required' });
        }

        const resets = await executeQuery(
            `SELECT pr.user_id, pr.expires_at, u.email 
             FROM password_resets pr 
             JOIN users u ON pr.user_id = u.id 
             WHERE pr.token = ? AND pr.expires_at > NOW() AND u.is_deleted = false`,
            [token]
        );

        if (resets.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        res.json({ 
            valid: true,
            email: resets[0].email 
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Reset password with token
router.post('/password-reset', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Token and new password are required' });
        }

        // Validate new password
        try {
            await EncryptionUtils.hashPassword(newPassword);
        } catch (validationError) {
            return res.status(400).json({ message: validationError.message });
        }

        const resets = await executeQuery(
            `SELECT user_id FROM password_resets 
             WHERE token = ? AND expires_at > NOW()`,
            [token]
        );

        if (resets.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const userId = resets[0].user_id;
        const passwordHash = await EncryptionUtils.hashPassword(newPassword);

        // Update password and track change time
        await executeQuery(
            'UPDATE users SET password_hash = ?, password_changed_at = NOW() WHERE id = ?',
            [passwordHash, userId]
        );

        // Delete used token
        await executeQuery('DELETE FROM password_resets WHERE token = ?', [token]);

        // Invalidate all sessions for security
        await invalidateUserSessions(userId);

        logSecurityEvent('PASSWORD_RESET_COMPLETED', req, { userId });

        res.json({ message: 'Password reset successful. Please login with your new password.' });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get active sessions for current user
router.get('/sessions', authenticateToken, async (req, res) => {
    try {
        const sessions = await executeQuery(
            `SELECT id, ip_address, user_agent, login_time, last_activity 
             FROM user_sessions 
             WHERE user_id = ? AND logout_time IS NULL 
             ORDER BY login_time DESC`,
            [req.user.id]
        );

        res.json(sessions.map(session => ({
            ...session,
            isCurrent: session.id === req.sessionId
        })));
    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Revoke specific session
router.delete('/sessions/:sessionId', authenticateToken, async (req, res) => {
    try {
        const sessionId = req.params.sessionId;

        // Verify session belongs to user
        const sessions = await executeQuery(
            'SELECT user_id FROM user_sessions WHERE id = ?',
            [sessionId]
        );

        if (sessions.length === 0 || sessions[0].user_id !== req.user.id) {
            return res.status(404).json({ message: 'Session not found' });
        }

        await invalidateSession(sessionId);

        logSecurityEvent('SESSION_REVOKED', req, { revokedSessionId: sessionId });
        res.json({ message: 'Session revoked successfully' });
    } catch (error) {
        console.error('Session revocation error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;