const cron = require('node-cron');
const emailService = require('../utils/emailService');
const { executeQuery } = require('../config/database');

// Daily low stock alerts at 8 AM
cron.schedule('0 8 * * *', async () => {
    console.log('Running daily low stock check...');
    try {
        const lowStockItems = await executeQuery(`
            SELECT name, sku, quantity, threshold 
            FROM inventory_items 
            WHERE quantity <= threshold AND is_deleted = false
        `);

        if (lowStockItems.length > 0) {
            const admins = await executeQuery(
                'SELECT email FROM users WHERE role = "Admin" AND is_deleted = false'
            );

            for (const admin of admins) {
                await emailService.sendLowStockAlert(admin.email, lowStockItems);
            }
        }
    } catch (error) {
        console.error('Low stock alert failed:', error);
    }
});

// Weekly inventory report on Monday at 9 AM
cron.schedule('0 9 * * 1', async () => {
    console.log('Generating weekly inventory report...');
    // Add your weekly report logic here
});

// Clean up expired password reset tokens every hour
cron.schedule('0 * * * *', async () => {
    try {
        await executeQuery(
            'DELETE FROM password_resets WHERE expires_at < NOW()'
        );
    } catch (error) {
        console.error('Token cleanup failed:', error);
    }
});

console.log('Scheduled tasks initialized');