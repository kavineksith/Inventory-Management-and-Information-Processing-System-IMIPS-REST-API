const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, trackActivity } = require('../middleware/auth');
const { fileUploadSecurity } = require('../middleware/security');

// Configure multer for email attachments
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads/attachments');
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'attachment-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit for attachments
});

// Configure email transporter
const createTransporter = () => {
    return nodemailer.createTransporter({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: process.env.SMTP_PORT || 587,
        secure: false,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });
};

// Get all emails
router.get('/', authenticateToken, requireRole(['Admin', 'Manager']), trackActivity, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        const emails = await executeQuery(`
      SELECT e.*, u.name as sent_by_name 
      FROM emails e 
      JOIN users u ON e.sent_by_user_id = u.id 
      WHERE e.is_deleted = false 
      ORDER BY e.created_at DESC 
      LIMIT ? OFFSET ?
    `, [parseInt(limit), parseInt(offset)]);

        // Get total count for pagination
        const countResult = await executeQuery(
            'SELECT COUNT(*) as total FROM emails WHERE is_deleted = false'
        );
        const total = countResult[0].total;

        res.json({
            emails,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get emails error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single email
router.get('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const emailId = req.params.id;

        const emails = await executeQuery(`
      SELECT e.*, u.name as sent_by_name 
      FROM emails e 
      JOIN users u ON e.sent_by_user_id = u.id 
      WHERE e.id = ? AND e.is_deleted = false
    `, [emailId]);

        if (emails.length === 0) {
            return res.status(404).json({ message: 'Email not found' });
        }

        res.json(emails[0]);
    } catch (error) {
        console.error('Get email error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Send email
router.post('/send', authenticateToken, requireRole(['Admin', 'Manager']), upload.single('attachment'), fileUploadSecurity, async (req, res) => {
    try {
        const { recipients, subject, body } = req.body;

        if (!recipients || !subject || !body) {
            return res.status(400).json({
                message: 'Recipients, subject, and body are required'
            });
        }

        // Validate recipients (basic email validation)
        const recipientList = recipients.split(',').map(email => email.trim());
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        for (const email of recipientList) {
            if (!emailRegex.test(email)) {
                return res.status(400).json({
                    message: `Invalid email address: ${email}`
                });
            }
        }

        const emailId = uuidv4();
        let attachmentPath = null;

        if (req.file) {
            attachmentPath = `/uploads/attachments/${req.file.filename}`;
        }

        // Save email record first
        await executeQuery(
            `INSERT INTO emails 
       (id, sent_by_user_id, recipient, subject, body, attachment_path) 
       VALUES (?, ?, ?, ?, ?, ?)`,
            [emailId, req.user.id, recipients, subject, body, attachmentPath]
        );

        // Send email
        const transporter = createTransporter();
        const mailOptions = {
            from: process.env.SMTP_USER,
            to: recipientList,
            subject: subject,
            html: body,
        };

        if (req.file) {
            mailOptions.attachments = [{
                filename: req.file.originalname,
                path: path.join(__dirname, '..', attachmentPath)
            }];
        }

        try {
            await transporter.sendMail(mailOptions);

            // Update email record with success status (you might want to add a status field to emails table)
            res.json({
                message: 'Email sent successfully',
                emailId
            });
        } catch (emailError) {
            console.error('Email sending failed:', emailError);

            // Mark email as failed (you might want to add a status field)
            await executeQuery(
                'UPDATE emails SET attachment_path = NULL WHERE id = ?',
                [emailId]
            );

            // Delete the attachment since email failed
            if (attachmentPath) {
                try {
                    await fs.unlink(path.join(__dirname, '..', attachmentPath));
                } catch (unlinkError) {
                    console.warn('Could not delete attachment:', unlinkError);
                }
            }

            throw new Error('Failed to send email: ' + emailError.message);
        }
    } catch (error) {
        console.error('Send email error:', error);
        res.status(500).json({ message: error.message || 'Internal server error' });
    }
});

// Send bulk emails (for newsletters, announcements)
router.post('/send-bulk', authenticateToken, requireRole(['Admin']), upload.single('attachment'), fileUploadSecurity, async (req, res) => {
    try {
        const { subject, body, recipient_group } = req.body;

        if (!subject || !body || !recipient_group) {
            return res.status(400).json({
                message: 'Subject, body, and recipient group are required'
            });
        }

        let recipientQuery = '';
        switch (recipient_group) {
            case 'all_customers':
                recipientQuery = `
          SELECT DISTINCT customer_email as email 
          FROM orders 
          WHERE customer_email IS NOT NULL AND customer_email != ''
          UNION
          SELECT DISTINCT customer_email as email 
          FROM customer_inquiries 
          WHERE customer_email IS NOT NULL AND customer_email != ''
        `;
                break;
            case 'recent_customers':
                recipientQuery = `
          SELECT DISTINCT customer_email as email 
          FROM orders 
          WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) 
          AND customer_email IS NOT NULL AND customer_email != ''
        `;
                break;
            case 'inquiry_customers':
                recipientQuery = `
          SELECT DISTINCT customer_email as email 
          FROM customer_inquiries 
          WHERE customer_email IS NOT NULL AND customer_email != ''
        `;
                break;
            default:
                return res.status(400).json({ message: 'Invalid recipient group' });
        }

        const recipientsResult = await executeQuery(recipientQuery);
        const recipients = recipientsResult.map(row => row.email);

        if (recipients.length === 0) {
            return res.status(400).json({ message: 'No recipients found for the selected group' });
        }

        // Send emails in batches to avoid overwhelming the SMTP server
        const batchSize = 10;
        const batches = [];

        for (let i = 0; i < recipients.length; i += batchSize) {
            batches.push(recipients.slice(i, i + batchSize));
        }

        let successCount = 0;
        let failCount = 0;

        for (const batch of batches) {
            const batchRecipients = batch.join(',');
            const emailId = uuidv4();
            let attachmentPath = null;

            if (req.file) {
                attachmentPath = `/uploads/attachments/${req.file.filename}`;
            }

            // Save email record
            await executeQuery(
                `INSERT INTO emails 
         (id, sent_by_user_id, recipient, subject, body, attachment_path) 
         VALUES (?, ?, ?, ?, ?, ?)`,
                [emailId, req.user.id, batchRecipients, subject, body, attachmentPath]
            );

            // Send email to batch
            const transporter = createTransporter();
            const mailOptions = {
                from: process.env.SMTP_USER,
                to: batch,
                subject: subject,
                html: body,
            };

            if (req.file) {
                mailOptions.attachments = [{
                    filename: req.file.originalname,
                    path: path.join(__dirname, '..', attachmentPath)
                }];
            }

            try {
                await transporter.sendMail(mailOptions);
                successCount += batch.length;
            } catch (emailError) {
                console.error('Batch email sending failed:', emailError);
                failCount += batch.length;

                // Mark email as failed
                await executeQuery(
                    'UPDATE emails SET attachment_path = NULL WHERE id = ?',
                    [emailId]
                );
            }
        }

        res.json({
            message: `Bulk email sending completed. Success: ${successCount}, Failed: ${failCount}`,
            total: recipients.length,
            successCount,
            failCount
        });
    } catch (error) {
        console.error('Send bulk email error:', error);
        res.status(500).json({ message: error.message || 'Internal server error' });
    }
});

// Delete email (soft delete)
router.delete('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const emailId = req.params.id;

        await executeQuery(
            'UPDATE emails SET is_deleted = true WHERE id = ?',
            [emailId]
        );

        res.json({ message: 'Email archived successfully' });
    } catch (error) {
        console.error('Delete email error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const emailId = req.params.id;

        // Get email to delete associated attachment
        const email = await executeQuery(
            'SELECT attachment_path FROM emails WHERE id = ?',
            [emailId]
        );

        if (email.length > 0 && email[0].attachment_path) {
            const attachmentPath = path.join(__dirname, '..', email[0].attachment_path);
            try {
                await fs.unlink(attachmentPath);
            } catch (error) {
                console.warn('Could not delete email attachment:', error);
            }
        }

        await executeQuery('DELETE FROM emails WHERE id = ?', [emailId]);
        res.json({ message: 'Email permanently deleted' });
    } catch (error) {
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get email statistics
router.get('/stats/overview', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const stats = await executeQuery(`
      SELECT 
        COUNT(*) as total_emails,
        COUNT(DISTINCT recipient) as unique_recipients,
        SUM(LENGTH(recipient) - LENGTH(REPLACE(recipient, ',', '')) + 1) as total_recipients
      FROM emails 
      WHERE is_deleted = false
    `);

        const recentEmails = await executeQuery(`
      SELECT e.*, u.name as sent_by_name 
      FROM emails e 
      JOIN users u ON e.sent_by_user_id = u.id 
      WHERE e.is_deleted = false 
      ORDER BY e.created_at DESC 
      LIMIT 10
    `);

        const emailsByDay = await executeQuery(`
      SELECT DATE(created_at) as date, COUNT(*) as count 
      FROM emails 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) 
      GROUP BY DATE(created_at) 
      ORDER BY date
    `);

        res.json({
            overview: stats[0],
            recentEmails,
            emailsByDay
        });
    } catch (error) {
        console.error('Get email stats error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;