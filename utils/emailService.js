const nodemailer = require('nodemailer');
const fs = require('fs-extra');
const path = require('path');

class EmailService {
    constructor() {
        this.transporter = null;
        this.initializeTransporter();
    }

    initializeTransporter() {
        // Validate SMTP configuration
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            console.warn('SMTP credentials not configured. Email functionality will be disabled.');
            return;
        }

        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
            tls: {
                rejectUnauthorized: process.env.NODE_ENV === 'production'
            }
        });

        // Verify connection
        this.transporter.verify((error, success) => {
            if (error) {
                console.error('SMTP connection failed:', error.message);
            } else {
                console.log('✓ Email service ready');
            }
        });
    }

    async sendEmail(to, subject, htmlContent, textContent = null, attachments = []) {
        if (!this.transporter) {
            throw new Error('Email service not configured');
        }

        const mailOptions = {
            from: `"${process.env.APP_NAME || 'IMIPS'}" <${process.env.SMTP_USER}>`,
            to,
            subject,
            html: htmlContent,
            text: textContent || this.stripHtml(htmlContent)
        };

        // Add attachments if provided
        if (attachments && attachments.length > 0) {
            mailOptions.attachments = attachments.map(att => ({
                filename: att.filename,
                path: att.path
            }));
        }

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('Email sent successfully:', info.messageId);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            console.error('Email sending failed:', error);
            throw new Error(`Failed to send email: ${error.message}`);
        }
    }

    // Password Reset Email
    async sendPasswordResetEmail(userEmail, userName, resetToken) {
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        const expiryTime = '1 hour';

        const htmlContent = this.getPasswordResetTemplate({
            userName,
            resetUrl,
            expiryTime,
            supportEmail: process.env.SUPPORT_EMAIL || process.env.SMTP_USER
        });

        const subject = 'Password Reset Request - IMIPS';

        return await this.sendEmail(userEmail, subject, htmlContent);
    }

    // Welcome Email for New Users
    async sendWelcomeEmail(userEmail, userName, temporaryPassword) {
        const loginUrl = `${process.env.FRONTEND_URL}/login`;

        const htmlContent = this.getWelcomeTemplate({
            userName,
            email: userEmail,
            temporaryPassword,
            loginUrl
        });

        const subject = 'Welcome to IMIPS - Your Account is Ready';

        return await this.sendEmail(userEmail, subject, htmlContent);
    }

    // Order Confirmation Email
    async sendOrderConfirmationEmail(customerEmail, orderDetails) {
        const htmlContent = this.getOrderConfirmationTemplate(orderDetails);
        const subject = `Order Confirmation #${orderDetails.orderId}`;

        return await this.sendEmail(customerEmail, subject, htmlContent);
    }

    // Low Stock Alert Email
    async sendLowStockAlert(adminEmail, lowStockItems) {
        const htmlContent = this.getLowStockAlertTemplate(lowStockItems);
        const subject = 'Low Stock Alert - Action Required';

        return await this.sendEmail(adminEmail, subject, htmlContent);
    }

    // Password Changed Notification
    async sendPasswordChangedNotification(userEmail, userName) {
        const htmlContent = this.getPasswordChangedTemplate({
            userName,
            supportEmail: process.env.SUPPORT_EMAIL || process.env.SMTP_USER,
            loginUrl: `${process.env.FRONTEND_URL}/login`
        });

        const subject = 'Your Password Has Been Changed';

        return await this.sendEmail(userEmail, subject, htmlContent);
    }

    // Email Templates
    getPasswordResetTemplate({ userName, resetUrl, expiryTime, supportEmail }) {
        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        .content { background: #f9f9f9; padding: 30px; }
        .button { 
            display: inline-block; 
            padding: 12px 30px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello ${userName},</p>
            
            <p>We received a request to reset your password for your IMIPS account. Click the button below to create a new password:</p>
            
            <div style="text-align: center;">
                <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #007bff;">${resetUrl}</p>
            
            <div class="warning">
                <strong>⚠ Important:</strong>
                <ul>
                    <li>This link will expire in ${expiryTime}</li>
                    <li>If you didn't request this reset, please ignore this email</li>
                    <li>Your password will remain unchanged until you create a new one</li>
                </ul>
            </div>
            
            <p>For security reasons, never share this link with anyone.</p>
            
            <p>If you need assistance, contact us at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
        </div>
        <div class="footer">
            <p>This is an automated email. Please do not reply to this message.</p>
            <p>&copy; ${new Date().getFullYear()} IMIPS. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    getWelcomeTemplate({ userName, email, temporaryPassword, loginUrl }) {
        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #28a745; color: white; padding: 20px; text-align: center; }
        .content { background: #f9f9f9; padding: 30px; }
        .credentials { background: white; border: 2px solid #007bff; padding: 15px; margin: 20px 0; }
        .button { 
            display: inline-block; 
            padding: 12px 30px; 
            background: #28a745; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px;
        }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to IMIPS!</h1>
        </div>
        <div class="content">
            <p>Hello ${userName},</p>
            
            <p>Your IMIPS account has been created successfully. Here are your login credentials:</p>
            
            <div class="credentials">
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Temporary Password:</strong> <code>${temporaryPassword}</code></p>
            </div>
            
            <p><strong style="color: #dc3545;">⚠ Important:</strong> Please change your password immediately after your first login.</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="${loginUrl}" class="button">Login Now</a>
            </div>
            
            <p>If you have any questions, please contact your system administrator.</p>
        </div>
        <div class="footer">
            <p>&copy; ${new Date().getFullYear()} IMIPS. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    getOrderConfirmationTemplate(orderDetails) {
        const itemsHtml = orderDetails.items.map(item => `
            <tr>
                <td>${item.name}</td>
                <td>${item.quantity}</td>
                <td>$${item.price.toFixed(2)}</td>
                <td>$${(item.quantity * item.price).toFixed(2)}</td>
            </tr>
        `).join('');

        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
        .total { font-size: 18px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Order Confirmation</h1>
            <p>Order #${orderDetails.orderId}</p>
        </div>
        <div style="padding: 30px;">
            <p>Hello ${orderDetails.customerName},</p>
            
            <p>Thank you for your order! Here are the details:</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Item</th>
                        <th>Quantity</th>
                        <th>Price</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
                <tfoot>
                    <tr>
                        <td colspan="3" style="text-align: right;"><strong>Subtotal:</strong></td>
                        <td>$${orderDetails.subtotal.toFixed(2)}</td>
                    </tr>
                    ${orderDetails.discount > 0 ? `
                    <tr>
                        <td colspan="3" style="text-align: right; color: green;"><strong>Discount:</strong></td>
                        <td style="color: green;">-$${orderDetails.discount.toFixed(2)}</td>
                    </tr>` : ''}
                    <tr class="total">
                        <td colspan="3" style="text-align: right;">Total:</td>
                        <td>$${orderDetails.total.toFixed(2)}</td>
                    </tr>
                </tfoot>
            </table>
            
            <p><strong>Shipping Address:</strong><br>${orderDetails.address}</p>
            
            <p>We'll send you another email when your order ships.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    getLowStockAlertTemplate(lowStockItems) {
        const itemsHtml = lowStockItems.map(item => `
            <tr style="background: ${item.quantity === 0 ? '#ffebee' : '#fff3cd'};">
                <td>${item.name}</td>
                <td>${item.sku}</td>
                <td><strong>${item.quantity}</strong></td>
                <td>${item.threshold}</td>
            </tr>
        `).join('');

        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
        th { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚠ Low Stock Alert</h1>
        </div>
        <div style="padding: 30px;">
            <p>The following items are low in stock or out of stock:</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Item Name</th>
                        <th>SKU</th>
                        <th>Current Stock</th>
                        <th>Threshold</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>
            
            <p><strong>Action Required:</strong> Please restock these items to avoid order fulfillment issues.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    getPasswordChangedTemplate({ userName, supportEmail, loginUrl }) {
        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #28a745; color: white; padding: 20px; text-align: center; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Changed Successfully</h1>
        </div>
        <div style="padding: 30px;">
            <p>Hello ${userName},</p>
            
            <p>This is to confirm that your password was changed successfully.</p>
            
            <div class="warning">
                <strong>⚠ Didn't change your password?</strong>
                <p>If you didn't make this change, please contact us immediately at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
            </div>
            
            <p>For your security, you've been logged out of all devices. Please <a href="${loginUrl}">log in again</a> with your new password.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    // Utility function to strip HTML tags for plain text version
    stripHtml(html) {
        return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    }
}

// Export singleton instance
module.exports = new EmailService();