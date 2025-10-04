const { executeQuery } = require('../config/database');
const emailService = require('./emailService');

async function sendNewsletterToCustomers(subject, htmlContent) {
    try {
        // Get all customer emails
        const customers = await executeQuery(`
            SELECT DISTINCT customer_email as email, customer_name as name 
            FROM orders 
            WHERE customer_email IS NOT NULL 
            AND customer_email != ''
            UNION
            SELECT DISTINCT customer_email as email, customer_name as name 
            FROM customer_inquiries 
            WHERE customer_email IS NOT NULL 
            AND customer_email != ''
        `);

        let successCount = 0;
        let failCount = 0;

        // Send in batches to avoid overwhelming SMTP server
        const batchSize = 10;
        for (let i = 0; i < customers.length; i += batchSize) {
            const batch = customers.slice(i, i + batchSize);

            await Promise.all(batch.map(async (customer) => {
                try {
                    // Personalize content
                    const personalizedContent = htmlContent.replace(
                        '{{NAME}}',
                        customer.name || 'Valued Customer'
                    );

                    await emailService.sendEmail(
                        customer.email,
                        subject,
                        personalizedContent
                    );
                    successCount++;
                } catch (error) {
                    console.error(`Failed to send to ${customer.email}:`, error.message);
                    failCount++;
                }
            }));

            // Delay between batches to avoid rate limiting
            if (i + batchSize < customers.length) {
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        console.log(`Newsletter sent: ${successCount} success, ${failCount} failed`);
        return { successCount, failCount };
    } catch (error) {
        console.error('Failed to send newsletter:', error);
        throw error;
    }
}

module.exports = {
    sendNewsletterToCustomers
}
