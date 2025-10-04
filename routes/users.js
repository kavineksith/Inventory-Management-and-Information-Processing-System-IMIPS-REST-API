const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const EncryptionUtils = require('../utils/encryption');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, canModifyUser, trackActivity } = require('../middleware/auth');
const { validateUserUpdate, validatePasswordChange } = require('../middleware/validation');
const { fileUploadSecurity } = require('../middleware/security');
const emailService = require('../utils/emailService');
const { notifyPasswordChanged } = require('../utils/password-change-notification');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads/profiles');
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'profile-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Get all users
router.get('/', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const users = await executeQuery(
            `SELECT id, name, email, role, profile_picture_url, last_activity, is_deleted, created_at 
       FROM users 
       WHERE is_deleted = false 
       ORDER BY created_at DESC`
        );
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update user
router.put('/:id', authenticateToken, canModifyUser, upload.single('profilePicture'), fileUploadSecurity, validateUserUpdate, async (req, res) => {
    try {
        const userId = req.params.id;
        const { name, email, role } = req.body;

        // Non-admin users cannot change roles
        if (role && req.user.role !== 'Admin') {
            return res.status(403).json({ message: 'Only administrators can change user roles' });
        }

        // Build update query dynamically
        const updates = [];
        const params = [];

        if (name) {
            updates.push('name = ?');
            params.push(name);
        }
        if (email) {
            updates.push('email = ?');
            params.push(email);
        }
        if (role && req.user.role === 'Admin') {
            updates.push('role = ?');
            params.push(role);
        }

        // Handle profile picture upload
        if (req.file) {
            const profilePictureUrl = `/uploads/profiles/${req.file.filename}`;
            updates.push('profile_picture_url = ?');
            params.push(profilePictureUrl);

            // Delete old profile picture if exists
            const oldUser = await executeQuery(
                'SELECT profile_picture_url FROM users WHERE id = ?',
                [userId]
            );

            if (oldUser[0]?.profile_picture_url) {
                const oldPath = path.join(__dirname, '..', oldUser[0].profile_picture_url);
                try {
                    await fs.unlink(oldPath);
                } catch (error) {
                    console.warn('Could not delete old profile picture:', error);
                }
            }
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(userId);

        await executeQuery(
            `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const updatedUser = await executeQuery(
            'SELECT id, name, email, role, profile_picture_url, last_activity, is_deleted FROM users WHERE id = ?',
            [userId]
        );

        res.json(updatedUser[0]);
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete user (soft delete)
router.delete('/:id', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const userId = req.params.id;

        // Prevent self-deletion
        if (userId === req.user.id) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }

        await executeQuery(
            'UPDATE users SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [userId]
        );

        res.json({ message: 'User archived successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const userId = req.params.id;

        if (userId === req.user.id) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }

        await executeQuery('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ message: 'User permanently deleted' });
    } catch (error) {
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get user sessions
router.get('/sessions', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const sessions = await executeQuery(`
      SELECT us.id, us.user_id, u.name as user_name, us.login_time, us.logout_time, us.duration_minutes 
      FROM user_sessions us 
      JOIN users u ON us.user_id = u.id 
      ORDER BY us.login_time DESC 
      LIMIT 100
    `);
        res.json(sessions);
    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Change password
router.post('/:id/change-password', authenticateToken, canModifyUser, validatePasswordChange, async (req, res) => {
    try {
        const userId = req.params.id;
        const { currentPassword, newPassword } = req.body;

        // Verify current password
        const user = await executeQuery(
            'SELECT password_hash FROM users WHERE id = ? AND is_deleted = false',
            [userId]
        );

        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isValidCurrentPassword = await EncryptionUtils.verifyPassword(currentPassword, user[0].password_hash);
        if (!isValidCurrentPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Hash new password
        const newPasswordHash = await EncryptionUtils.hashPassword(newPassword);

        await executeQuery(
            'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [newPasswordHash, userId]
        );

        await notifyPasswordChanged(userId, user.email, user.name);

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Reset password (Admin only)
router.post('/:id/reset-password', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const userId = req.params.id;
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({ message: 'New password is required' });
        }

        const newPasswordHash = await EncryptionUtils.hashPassword(newPassword);

        await executeQuery(
            'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [newPasswordHash, userId]
        );

        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Activity heartbeat
router.post('/activity', authenticateToken, async (req, res) => {
    try {
        await executeQuery(
            'UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = ?',
            [req.user.id]
        );
        res.status(204).send();
    } catch (error) {
        console.error('Activity update error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;