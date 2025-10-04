const emailService = require("./emailService");

async function sendOrderStatusUpdateEmail(order, newStatus) {
    try {
        const statusMessages = {
            'Processing': 'Your order is being processed',
            'Shipped': 'Your order has been shipped!',
            'Delivered': 'Your order has been delivered',
            'Cancelled': 'Your order has been cancelled',
            'Refunded': 'Your order has been refunded'
        };

        const subject = `Order #${order.id} - ${statusMessages[newStatus]}`;
        const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        .status { 
            background: #28a745; 
            color: white; 
            padding: 15px; 
            text-align: center; 
            font-size: 18px;
            margin: 20px 0;
        }
        .content { padding: 30px; background: #f9f9f9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Order Status Update</h2>
        </div>
        <div class="status">
            ${statusMessages[newStatus]}
        </div>
        <div class="content">
            <p>Hello ${order.customer_name},</p>
            
            <p>Your order #${order.id} status has been updated to: <strong>${newStatus}</strong></p>
            
            ${newStatus === 'Shipped' ? `
                <p>Your order is on its way! You should receive it within 3-5 business days.</p>
            ` : ''}
            
            ${newStatus === 'Delivered' ? `
                <p>We hope you enjoy your purchase! If you have any issues, please contact us.</p>
            ` : ''}
            
            <p><strong>Order Total:</strong> ${order.total.toFixed(2)}</p>
            
            <p>Thank you for your business!</p>
        </div>
    </div>
</body>
</html>
        `;

        await emailService.sendEmail(
            order.customer_email,
            subject,
            htmlContent
        );

        console.log('Order status update sent for:', order.id);
    } catch (error) {
        console.error('Failed to send order status update:', error);
    }
}

async function sendInquiryResponseEmail(inquiry, responseMessage) {
    try {
        const subject = `Re: Your Inquiry - ${inquiry.id}`;
        const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; }
        .content { padding: 30px; background: #f9f9f9; }
        .original { background: #e9ecef; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Response to Your Inquiry</h2>
        </div>
        <div class="content">
            <p>Hello ${inquiry.customer_name},</p>
            
            <p>${responseMessage}</p>
            
            <div class="original">
                <strong>Your Original Inquiry:</strong>
                <p>${inquiry.inquiry_details}</p>
            </div>
            
            <p>If you have any further questions, please don't hesitate to contact us.</p>
            
            <p>Best regards,<br>IMIPS Support Team</p>
        </div>
    </div>
</body>
</html>
        `;

        await emailService.sendEmail(
            inquiry.customer_email,
            subject,
            htmlContent
        );

        console.log('Inquiry response sent for:', inquiry.id);
    } catch (error) {
        console.error('Failed to send inquiry response:', error);
    }
}

module.exports = {
    sendOrderStatusUpdateEmail,
    sendInquiryResponseEmail
}