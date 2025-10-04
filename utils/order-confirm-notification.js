const emailService = require("./emailService");

async function sendOrderConfirmationEmail(order) {
    try {
        const orderDetails = {
            orderId: order.id,
            customerName: order.customer_name,
            address: order.customer_address,
            items: order.items.map(item => ({
                name: item.name,
                quantity: item.quantity,
                price: item.price_at_purchase
            })),
            subtotal: order.subtotal,
            discount: order.discount_amount,
            total: order.total
        };

        await emailService.sendOrderConfirmationEmail(
            order.customer_email,
            orderDetails
        );

        console.log('Order confirmation sent for order:', order.id);
    } catch (error) {
        console.error('Failed to send order confirmation:', error);
        // Don't fail the order creation if email fails
    }
}

module.exports = {
    sendOrderConfirmationEmail
}