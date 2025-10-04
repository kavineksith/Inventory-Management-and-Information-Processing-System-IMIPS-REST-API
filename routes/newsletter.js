const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { fileUploadSecurity } = require('../middleware/security');
const emailService = require('../utils/emailService');
const { body, validationResult } = require('express-validator');

// Get newsletter subscribers
async function getNewsletterSubscribers() {
    return await executeQuery(`
        SELECT email, name 
        FROM newsletter_subscriptions 
        WHERE subscribed = true
    `);
}

// Configure multer for newsletter attachments
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads/newsletters');
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'newsletter-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 3 // Maximum 3 attachments
    },
    fileFilter: (req, file, cb) => {
        // Allowed file types
        const allowedTypes = [
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        ];

        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Allowed: PDF, Images, Word, Excel'));
        }
    }
});

// Validation middleware
const validateNewsletter = [
    body('subject')
        .trim()
        .isLength({ min: 5, max: 200 })
        .withMessage('Subject must be between 5 and 200 characters'),
    body('htmlContent')
        .trim()
        .isLength({ min: 50, max: 100000 })
        .withMessage('Content must be between 50 and 100,000 characters')
        .custom((value) => {
            if (!value.includes('<') || !value.includes('>')) {
                throw new Error('Content must be valid HTML');
            }
            if (/<script/i.test(value)) {
                throw new Error('Script tags are not allowed');
            }
            return true;
        }),
    body('recipientGroup')
        .isIn(['subscribers', 'all_customers', 'recent_customers', 'inquiry_customers', 'custom'])
        .withMessage('Invalid recipient group'),
    body('customEmails')
        .optional()
        .custom((value) => {
            if (value) {
                const emails = value.split(',').map(e => e.trim());
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

                if (emails.length > 1000) {
                    throw new Error('Maximum 1000 custom email addresses allowed');
                }

                for (const email of emails) {
                    if (!emailRegex.test(email)) {
                        throw new Error(`Invalid email address: ${email}`);
                    }
                }
            }
            return true;
        })
];

// Send newsletter
router.post('/send',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    upload.array('attachments', 3),
    fileUploadSecurity,
    validateNewsletter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                // Clean up uploaded files on validation error
                if (req.files) {
                    for (const file of req.files) {
                        await fs.unlink(file.path).catch(console.error);
                    }
                }
                return res.status(400).json({
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { subject, htmlContent, recipientGroup, customEmails } = req.body;

            // Get unique recipients based on group
            let recipients = [];

            if (recipientGroup === 'custom' && customEmails) {
                recipients = customEmails.split(',').map(e => ({
                    email: e.trim(),
                    name: 'Customer'
                }));
            } else {
                recipients = await getRecipientsByGroup(recipientGroup);
            }

            // Remove duplicates by email
            const uniqueRecipients = Array.from(
                new Map(recipients.map(r => [r.email.toLowerCase(), r])).values()
            );

            if (uniqueRecipients.length === 0) {
                // Clean up files
                if (req.files) {
                    for (const file of req.files) {
                        await fs.unlink(file.path).catch(console.error);
                    }
                }
                return res.status(400).json({
                    message: 'No valid recipients found'
                });
            }

            // Prepare attachments
            const attachments = req.files ? req.files.map(file => ({
                filename: file.originalname,
                path: file.path
            })) : [];

            // Save newsletter record
            const newsletterId = uuidv4();
            await executeQuery(
                `INSERT INTO newsletters 
                (id, subject, html_content, recipient_group, total_recipients, sent_by_user_id, status) 
                VALUES (?, ?, ?, ?, ?, ?, 'sending')`,
                [newsletterId, subject, htmlContent, recipientGroup, uniqueRecipients.length, req.user.id]
            );

            // Send in background (don't wait)
            sendNewsletterAsync(newsletterId, subject, htmlContent, uniqueRecipients, attachments)
                .catch(error => console.error('Newsletter sending error:', error));

            res.json({
                message: 'Newsletter is being sent',
                newsletterId,
                totalRecipients: uniqueRecipients.length,
                estimatedTime: Math.ceil(uniqueRecipients.length / 10) * 2 + ' seconds'
            });

        } catch (error) {
            // Clean up files on error
            if (req.files) {
                for (const file of req.files) {
                    await fs.unlink(file.path).catch(console.error);
                }
            }
            console.error('Send newsletter error:', error);
            res.status(500).json({ message: 'Failed to send newsletter' });
        }
    }
);

// Get recipients by group
async function getRecipientsByGroup(group) {
    let query = '';

    switch (group) {
        case 'subscribers':
            // New option for newsletter subscribers
            return await getNewsletterSubscribers();
        case 'all_customers':
            query = `
                SELECT DISTINCT customer_email as email, customer_name as name 
                FROM orders 
                WHERE customer_email IS NOT NULL AND customer_email != '' AND is_deleted = false
                UNION
                SELECT DISTINCT customer_email as email, customer_name as name 
                FROM customer_inquiries 
                WHERE customer_email IS NOT NULL AND customer_email != '' AND is_deleted = false
            `;
            break;

        case 'recent_customers':
            query = `
                SELECT DISTINCT customer_email as email, customer_name as name 
                FROM orders 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) 
                AND customer_email IS NOT NULL AND customer_email != '' AND is_deleted = false
            `;
            break;

        case 'inquiry_customers':
            query = `
                SELECT DISTINCT customer_email as email, customer_name as name 
                FROM customer_inquiries 
                WHERE customer_email IS NOT NULL AND customer_email != '' AND is_deleted = false
            `;
            break;

        default:
            return [];
    }

    return await executeQuery(query);
}

// Send newsletter asynchronously
async function sendNewsletterAsync(newsletterId, subject, htmlContent, recipients, attachments) {
    let successCount = 0;
    let failCount = 0;
    const failedEmails = [];

    try {
        const batchSize = 10;

        for (let i = 0; i < recipients.length; i += batchSize) {
            const batch = recipients.slice(i, i + batchSize);

            await Promise.all(batch.map(async (recipient) => {
                try {
                    // Personalize content
                    const unsubscribeUrl = `${process.env.FRONTEND_URL}/unsubscribe?email=${encodeURIComponent(recipient.email)}`;

                    const personalizedContent = htmlContent
                        .replace(/\{\{NAME\}\}/g, recipient.name || 'Valued Customer')
                        .replace(/\{\{EMAIL\}\}/g, recipient.email)
                        + `
    <div style="text-align: center; padding: 20px; font-size: 12px; color: #666; border-top: 1px solid #ddd; margin-top: 30px;">
        <p>You're receiving this because you subscribed to our newsletter.</p>
        <p><a href="${unsubscribeUrl}" style="color: #007bff;">Unsubscribe</a> from future emails</p>
    </div>
    `;

                    await emailService.sendEmail(
                        recipient.email,
                        subject,
                        personalizedContent,
                        null,
                        attachments
                    );

                    successCount++;
                } catch (error) {
                    console.error(`Failed to send to ${recipient.email}:`, error.message);
                    failCount++;
                    failedEmails.push(recipient.email);
                }
            }));

            // Delay between batches
            if (i + batchSize < recipients.length) {
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        // Update newsletter status
        await executeQuery(
            `UPDATE newsletters 
            SET status = 'completed', success_count = ?, fail_count = ?, 
                failed_emails = ?, completed_at = NOW() 
            WHERE id = ?`,
            [successCount, failCount, failedEmails.join(','), newsletterId]
        );

        // Clean up attachments after sending
        for (const attachment of attachments) {
            await fs.unlink(attachment.path).catch(console.error);
        }

    } catch (error) {
        console.error('Newsletter sending error:', error);

        // Mark as failed
        await executeQuery(
            `UPDATE newsletters 
            SET status = 'failed', success_count = ?, fail_count = ?, 
                error_message = ?, completed_at = NOW() 
            WHERE id = ?`,
            [successCount, failCount, error.message, newsletterId]
        );
    }
}

// Get newsletter history
router.get('/history',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const { page = 1, limit = 20 } = req.query;
            const offset = (page - 1) * limit;

            const newsletters = await executeQuery(`
                SELECT n.*, u.name as sent_by_name 
                FROM newsletters n 
                JOIN users u ON n.sent_by_user_id = u.id 
                ORDER BY n.created_at DESC 
                LIMIT ? OFFSET ?
            `, [parseInt(limit), parseInt(offset)]);

            const countResult = await executeQuery(
                'SELECT COUNT(*) as total FROM newsletters'
            );

            res.json({
                newsletters,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: countResult[0].total,
                    pages: Math.ceil(countResult[0].total / limit)
                }
            });
        } catch (error) {
            console.error('Get newsletter history error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
);

// Get newsletter details
router.get('/:id',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const newsletters = await executeQuery(`
                SELECT n.*, u.name as sent_by_name 
                FROM newsletters n 
                JOIN users u ON n.sent_by_user_id = u.id 
                WHERE n.id = ?
            `, [req.params.id]);

            if (newsletters.length === 0) {
                return res.status(404).json({ message: 'Newsletter not found' });
            }

            res.json(newsletters[0]);
        } catch (error) {
            console.error('Get newsletter error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
);

// Get newsletter statistics
router.get('/stats/overview',
    authenticateToken,
    requireRole(['Admin', 'Manager']),
    async (req, res) => {
        try {
            const stats = await executeQuery(`
                SELECT 
                    COUNT(*) as total_sent,
                    SUM(success_count) as total_delivered,
                    SUM(fail_count) as total_failed,
                    SUM(total_recipients) as total_recipients,
                    AVG(success_count / total_recipients * 100) as avg_delivery_rate
                FROM newsletters
            `);

            const recentNewsletters = await executeQuery(`
                SELECT n.*, u.name as sent_by_name 
                FROM newsletters n 
                JOIN users u ON n.sent_by_user_id = u.id 
                ORDER BY n.created_at DESC 
                LIMIT 10
            `);

            res.json({
                overview: stats[0],
                recent: recentNewsletters
            });
        } catch (error) {
            console.error('Get newsletter stats error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
);

module.exports = router;