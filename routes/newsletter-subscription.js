const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

// Validation middleware
const validateSubscription = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email address required'),
    body('name')
        .optional()
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Name must be between 2-255 characters')
];

// Public endpoint - Subscribe to newsletter
router.post('/subscribe', validateSubscription, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { email, name, source = 'manual' } = req.body;

        // Check if already subscribed
        const existing = await executeQuery(
            'SELECT id, subscribed FROM newsletter_subscriptions WHERE email = ?',
            [email]
        );

        if (existing.length > 0) {
            if (existing[0].subscribed) {
                return res.status(200).json({
                    message: 'Already subscribed to newsletter'
                });
            } else {
                // Resubscribe
                await executeQuery(
                    `UPDATE newsletter_subscriptions 
                    SET subscribed = true, subscribed_at = NOW(), unsubscribed_at = NULL 
                    WHERE email = ?`,
                    [email]
                );
                return res.json({ message: 'Successfully resubscribed!' });
            }
        }

        // New subscription
        await executeQuery(
            `INSERT INTO newsletter_subscriptions (email, name, source, subscribed) 
            VALUES (?, ?, ?, true)`,
            [email, name, source]
        );

        res.status(201).json({
            message: 'Successfully subscribed to newsletter!'
        });

    } catch (error) {
        console.error('Subscribe error:', error);
        res.status(500).json({ message: 'Subscription failed' });
    }
});

// Public endpoint - Unsubscribe from newsletter
router.post('/unsubscribe', [
    body('email').isEmail().normalizeEmail()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                message: 'Valid email required'
            });
        }

        const { email } = req.body;

        const result = await executeQuery(
            `UPDATE newsletter_subscriptions 
            SET subscribed = false, unsubscribed_at = NOW() 
            WHERE email = ? AND subscribed = true`,
            [email]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: 'Email not found in subscription list'
            });
        }

        res.json({ message: 'Successfully unsubscribed' });

    } catch (error) {
        console.error('Unsubscribe error:', error);
        res.status(500).json({ message: 'Unsubscribe failed' });
    }
});

// Admin endpoints (require authentication)
const { authenticateToken, requireRole } = require('../middleware/auth');

// Get all subscriptions
router.get('/',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const { subscribed, page = 1, limit = 50 } = req.query;
            const offset = (page - 1) * limit;

            let query = 'SELECT * FROM newsletter_subscriptions WHERE 1=1';
            const params = [];

            if (subscribed !== undefined) {
                query += ' AND subscribed = ?';
                params.push(subscribed === 'true');
            }

            query += ' ORDER BY subscribed_at DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));

            const subscriptions = await executeQuery(query, params);

            // Get total count
            let countQuery = 'SELECT COUNT(*) as total FROM newsletter_subscriptions WHERE 1=1';
            const countParams = [];
            if (subscribed !== undefined) {
                countQuery += ' AND subscribed = ?';
                countParams.push(subscribed === 'true');
            }

            const countResult = await executeQuery(countQuery, countParams);

            res.json({
                subscriptions,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: countResult[0].total,
                    pages: Math.ceil(countResult[0].total / limit)
                }
            });

        } catch (error) {
            console.error('Get subscriptions error:', error);
            res.status(500).json({ message: 'Failed to fetch subscriptions' });
        }
    }
);

// Export subscriptions as CSV
router.get('/export',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const { subscribed } = req.query;

            let query = 'SELECT * FROM newsletter_subscriptions WHERE 1=1';
            const params = [];

            if (subscribed !== undefined) {
                query += ' AND subscribed = ?';
                params.push(subscribed === 'true');
            }

            const subscriptions = await executeQuery(query, params);

            // Generate CSV
            const csv = ['Email,Name,Subscribed,Subscribed At,Source'];
            subscriptions.forEach(sub => {
                csv.push([
                    sub.email,
                    sub.name || '',
                    sub.subscribed ? 'Yes' : 'No',
                    new Date(sub.subscribed_at).toISOString(),
                    sub.source
                ].join(','));
            });

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=newsletter-subscriptions-${Date.now()}.csv`);
            res.send(csv.join('\n'));

        } catch (error) {
            console.error('Export error:', error);
            res.status(500).json({ message: 'Export failed' });
        }
    }
);

// Get subscription statistics
router.get('/stats',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const stats = await executeQuery(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN subscribed = true THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN subscribed = false THEN 1 ELSE 0 END) as unsubscribed,
                    SUM(CASE WHEN source = 'order' THEN 1 ELSE 0 END) as from_orders,
                    SUM(CASE WHEN source = 'inquiry' THEN 1 ELSE 0 END) as from_inquiries,
                    SUM(CASE WHEN source = 'manual' THEN 1 ELSE 0 END) as from_manual
                FROM newsletter_subscriptions
            `);

            const recentSubscribers = await executeQuery(`
                SELECT email, name, subscribed_at, source
                FROM newsletter_subscriptions
                WHERE subscribed = true
                ORDER BY subscribed_at DESC
                LIMIT 10
            `);

            res.json({
                overview: stats[0],
                recent: recentSubscribers
            });

        } catch (error) {
            console.error('Stats error:', error);
            res.status(500).json({ message: 'Failed to fetch stats' });
        }
    }
);

module.exports = router;