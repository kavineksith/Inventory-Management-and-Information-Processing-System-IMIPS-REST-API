require('dotenv').config();
const emailService = require('./utils/emailService');

async function testEmail() {
    try {
        console.log('Testing email service...');

        await emailService.sendEmail(
            'recipient@example.com',
            'Test Email from IMIPS',
            '<h1>Test Email</h1><p>If you receive this, email is working!</p>',
            'Test Email - If you receive this, email is working!'
        );

        console.log('✓ Email sent successfully!');
    } catch (error) {
        console.error('✗ Email test failed:', error.message);
    }
}

testEmail();