const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, trackActivity } = require('../middleware/auth');
const { validateInquiry } = require('../middleware/validation');
const { fileUploadSecurity } = require('../middleware/security');
const emailService = require('../utils/emailService');
const { body, validationResult } = require('express-validator');

// Configure multer for inquiry response attachments
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads/inquiry-responses');
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'response-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB per file
        files: 5 // Maximum 5 attachments
    },
    fileFilter: (req, file, cb) => {
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

// Validation for inquiry response
const validateInquiryResponse = [
    body('responseMessage')
        .trim()
        .isLength({ min: 10, max: 5000 })
        .withMessage('Response message must be between 10 and 5000 characters')
        .custom((value) => {
            if (/<script/i.test(value)) {
                throw new Error('Script tags are not allowed');
            }
            return true;
        })
];

// Get all inquiries
router.get('/', authenticateToken, trackActivity, async (req, res) => {
    try {
        const { status, assigned_to, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = `
      SELECT ci.*, u.name as assigned_user_name 
      FROM customer_inquiries ci 
      LEFT JOIN users u ON ci.assigned_user_id = u.id 
      WHERE ci.is_deleted = false
    `;
        const params = [];

        if (status && status !== 'all') {
            query += ' AND ci.status = ?';
            params.push(status);
        }

        if (assigned_to && assigned_to !== 'all') {
            if (assigned_to === 'unassigned') {
                query += ' AND ci.assigned_user_id IS NULL';
            } else {
                query += ' AND ci.assigned_user_id = ?';
                params.push(assigned_to);
            }
        }

        query += ' ORDER BY ci.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const inquiries = await executeQuery(query, params);

        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as total FROM customer_inquiries WHERE is_deleted = false';
        const countParams = [];

        if (status && status !== 'all') {
            countQuery += ' AND status = ?';
            countParams.push(status);
        }

        if (assigned_to && assigned_to !== 'all') {
            if (assigned_to === 'unassigned') {
                countQuery += ' AND assigned_user_id IS NULL';
            } else {
                countQuery += ' AND assigned_user_id = ?';
                countParams.push(assigned_to);
            }
        }

        const countResult = await executeQuery(countQuery, countParams);
        const total = countResult[0].total;

        res.json({
            inquiries,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get inquiries error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single inquiry
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const inquiryId = req.params.id;

        const inquiries = await executeQuery(`
      SELECT ci.*, u.name as assigned_user_name 
      FROM customer_inquiries ci 
      LEFT JOIN users u ON ci.assigned_user_id = u.id 
      WHERE ci.id = ? AND ci.is_deleted = false
    `, [inquiryId]);

        if (inquiries.length === 0) {
            return res.status(404).json({ message: 'Inquiry not found' });
        }

        res.json(inquiries[0]);
    } catch (error) {
        console.error('Get inquiry error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create new inquiry
router.post('/', authenticateToken, validateInquiry, async (req, res) => {
    try {
        const {
            customer_name,
            customer_email,
            inquiry_details
        } = req.body;

        const inquiryId = uuidv4();

        await executeQuery(
            `INSERT INTO customer_inquiries 
       (id, customer_name, customer_email, inquiry_details) 
       VALUES (?, ?, ?, ?)`,
            [inquiryId, customer_name, customer_email, inquiry_details]
        );

        const newInquiry = await executeQuery(
            'SELECT * FROM customer_inquiries WHERE id = ?',
            [inquiryId]
        );

        res.status(201).json(newInquiry[0]);

        // Auto-subscribe to newsletter if not already subscribed
        try {
            const existing = await executeQuery(
                'SELECT id FROM newsletter_subscriptions WHERE email = ?',
                [customer_email]
            );

            if (existing.length === 0) {
                await executeQuery(
                    `INSERT INTO newsletter_subscriptions (email, name, source, subscribed) 
            VALUES (?, ?, 'order', true)`,
                    [customer_email, customer_name]
                );
            }
        } catch (error) {
            console.warn('Failed to auto-subscribe to newsletter:', error);
            // Don't fail the order if subscription fails
        }
    } catch (error) {
        console.error('Create inquiry error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update inquiry
router.put('/:id', authenticateToken, async (req, res) => {
    try {
        const inquiryId = req.params.id;
        const { status, assigned_user_id, inquiry_details } = req.body;

        // Check if inquiry exists
        const existingInquiry = await executeQuery(
            'SELECT * FROM customer_inquiries WHERE id = ? AND is_deleted = false',
            [inquiryId]
        );

        if (existingInquiry.length === 0) {
            return res.status(404).json({ message: 'Inquiry not found' });
        }

        // Build update query
        const updates = [];
        const params = [];

        if (status) {
            const validStatuses = ['Pending', 'In Progress', 'Completed'];
            if (!validStatuses.includes(status)) {
                return res.status(400).json({ message: 'Invalid status' });
            }
            updates.push('status = ?');
            params.push(status);
        }

        if (assigned_user_id !== undefined) {
            if (assigned_user_id === null) {
                updates.push('assigned_user_id = NULL');
            } else {
                // Verify assigned user exists
                const user = await executeQuery(
                    'SELECT id FROM users WHERE id = ? AND is_deleted = false',
                    [assigned_user_id]
                );
                if (user.length === 0) {
                    return res.status(400).json({ message: 'Assigned user not found' });
                }
                updates.push('assigned_user_id = ?');
                params.push(assigned_user_id);
            }
        }

        if (inquiry_details) {
            updates.push('inquiry_details = ?');
            params.push(inquiry_details);
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(inquiryId);

        await executeQuery(
            `UPDATE customer_inquiries SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const updatedInquiry = await executeQuery(`
      SELECT ci.*, u.name as assigned_user_name 
      FROM customer_inquiries ci 
      LEFT JOIN users u ON ci.assigned_user_id = u.id 
      WHERE ci.id = ?
    `, [inquiryId]);

        res.json(updatedInquiry[0]);
    } catch (error) {
        console.error('Update inquiry error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Assign inquiry to current user
router.post('/:id/assign-to-me', authenticateToken, async (req, res) => {
    try {
        const inquiryId = req.params.id;

        const result = await executeQuery(
            'UPDATE customer_inquiries SET assigned_user_id = ?, status = "In Progress", updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_deleted = false',
            [req.user.id, inquiryId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Inquiry not found' });
        }

        const updatedInquiry = await executeQuery(`
      SELECT ci.*, u.name as assigned_user_name 
      FROM customer_inquiries ci 
      LEFT JOIN users u ON ci.assigned_user_id = u.id 
      WHERE ci.id = ?
    `, [inquiryId]);

        res.json(updatedInquiry[0]);
    } catch (error) {
        console.error('Assign inquiry error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Send response to inquiry (NEW ENDPOINT)
router.post('/:id/respond',
    authenticateToken,
    upload.array('attachments', 5),
    fileUploadSecurity,
    validateInquiryResponse,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                // Clean up uploaded files
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

            const inquiryId = req.params.id;
            const { responseMessage } = req.body;

            // Get inquiry details
            const inquiries = await executeQuery(
                `SELECT * FROM customer_inquiries WHERE id = ? AND is_deleted = false`,
                [inquiryId]
            );

            if (inquiries.length === 0) {
                // Clean up files
                if (req.files) {
                    for (const file of req.files) {
                        await fs.unlink(file.path).catch(console.error);
                    }
                }
                return res.status(404).json({ message: 'Inquiry not found' });
            }

            const inquiry = inquiries[0];

            // Check total attachment size
            if (req.files && req.files.length > 0) {
                const totalSize = req.files.reduce((sum, file) => sum + file.size, 0);
                if (totalSize > 5 * 1024 * 1024) {
                    for (const file of req.files) {
                        await fs.unlink(file.path).catch(console.error);
                    }
                    return res.status(400).json({
                        message: 'Total attachment size cannot exceed 5MB'
                    });
                }
            }

            // Prepare attachments
            const attachments = req.files ? req.files.map(file => ({
                filename: file.originalname,
                path: file.path
            })) : [];

            // Send response email
            const subject = `Re: Your Inquiry - ${inquiry.id}`;
            const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { padding: 30px; background: #f9f9f9; }
        .original { background: #e9ecef; padding: 15px; margin: 20px 0; border-left: 4px solid #007bff; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Response to Your Inquiry</h2>
        </div>
        <div class="content">
            <p>Hello ${inquiry.customer_name},</p>
            
            <p>${responseMessage.replace(/\n/g, '<br>')}</p>
            
            <div class="original">
                <strong>Your Original Inquiry:</strong>
                <p>${inquiry.inquiry_details}</p>
                <p><small>Submitted on: ${new Date(inquiry.created_at).toLocaleString()}</small></p>
            </div>
            
            ${attachments.length > 0 ? `
            <p><strong>Attachments:</strong></p>
            <ul>
                ${attachments.map(att => `<li>${att.filename}</li>`).join('')}
            </ul>
            ` : ''}
            
            <p>If you have any further questions, please don't hesitate to contact us.</p>
            
            <p>Best regards,<br>${req.user.name}<br>IMIPS Support Team</p>
        </div>
        <div class="footer">
            <p>This email was sent in response to your inquiry #${inquiry.id}</p>
            <p>&copy; ${new Date().getFullYear()} IMIPS. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            `;

            try {
                await emailService.sendEmail(
                    inquiry.customer_email,
                    subject,
                    htmlContent,
                    null,
                    attachments
                );

                // Update inquiry status to completed
                await executeQuery(
                    `UPDATE customer_inquiries 
                    SET status = 'Completed', updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?`,
                    [inquiryId]
                );

                // Save response record
                await executeQuery(
                    `INSERT INTO inquiry_responses 
                    (id, inquiry_id, response_message, responded_by_user_id, has_attachments) 
                    VALUES (?, ?, ?, ?, ?)`,
                    [uuidv4(), inquiryId, responseMessage, req.user.id, attachments.length > 0]
                );

                // Clean up attachments after sending
                for (const attachment of attachments) {
                    await fs.unlink(attachment.path).catch(console.error);
                }

                res.json({
                    message: 'Response sent successfully',
                    inquiryId,
                    sentTo: inquiry.customer_email
                });

            } catch (emailError) {
                console.error('Failed to send inquiry response:', emailError);

                // Clean up files
                for (const attachment of attachments) {
                    await fs.unlink(attachment.path).catch(console.error);
                }

                res.status(500).json({
                    message: 'Failed to send email response',
                    error: emailError.message
                });
            }

        } catch (error) {
            // Clean up files on error
            if (req.files) {
                for (const file of req.files) {
                    await fs.unlink(file.path).catch(console.error);
                }
            }
            console.error('Inquiry response error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
);

// Get inquiry responses (NEW ENDPOINT)
router.get('/:id/responses', authenticateToken, async (req, res) => {
    try {
        const inquiryId = req.params.id;

        const responses = await executeQuery(`
            SELECT ir.*, u.name as responded_by_name 
            FROM inquiry_responses ir 
            JOIN users u ON ir.responded_by_user_id = u.id 
            WHERE ir.inquiry_id = ? 
            ORDER BY ir.created_at DESC
        `, [inquiryId]);

        res.json(responses);
    } catch (error) {
        console.error('Get inquiry responses error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete inquiry (soft delete)
router.delete('/:id', authenticateToken, async (req, res) => {
    try {
        const inquiryId = req.params.id;

        await executeQuery(
            'UPDATE customer_inquiries SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [inquiryId]
        );

        res.json({ message: 'Inquiry archived successfully' });
    } catch (error) {
        console.error('Delete inquiry error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const inquiryId = req.params.id;

        await executeQuery('DELETE FROM customer_inquiries WHERE id = ?', [inquiryId]);
        res.json({ message: 'Inquiry permanently deleted' });
    } catch (error) {
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get inquiry statistics
router.get('/stats/overview', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const stats = await executeQuery(`
      SELECT 
        COUNT(*) as total_inquiries,
        SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending_inquiries,
        SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress_inquiries,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_inquiries,
        SUM(CASE WHEN assigned_user_id IS NULL THEN 1 ELSE 0 END) as unassigned_inquiries,
        AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(updated_at, NOW()))) as avg_resolution_hours
      FROM customer_inquiries 
      WHERE is_deleted = false
    `);

        const recentInquiries = await executeQuery(`
      SELECT ci.*, u.name as assigned_user_name 
      FROM customer_inquiries ci 
      LEFT JOIN users u ON ci.assigned_user_id = u.id 
      WHERE ci.is_deleted = false 
      ORDER BY ci.created_at DESC 
      LIMIT 10
    `);

        const inquiriesByDay = await executeQuery(`
      SELECT DATE(created_at) as date, COUNT(*) as count 
      FROM customer_inquiries 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) 
      GROUP BY DATE(created_at) 
      ORDER BY date
    `);

        res.json({
            overview: stats[0],
            recentInquiries,
            inquiriesByDay
        });
    } catch (error) {
        console.error('Get inquiry stats error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;