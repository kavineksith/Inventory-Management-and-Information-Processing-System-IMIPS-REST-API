const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, trackActivity } = require('../middleware/auth');
const { validateOrder } = require('../middleware/validation');
const { sendOrderStatusUpdateEmail } = require('../utils/emailTemplates');
const { sendOrderConfirmationEmail } = require('../utils/order-confirm-notification');

// Get all orders
router.get('/', authenticateToken, trackActivity, async (req, res) => {
    try {
        const { status, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = `
      SELECT o.*, u.name as created_by_name, d.code as discount_code 
      FROM orders o 
      LEFT JOIN users u ON o.created_by_user_id = u.id 
      LEFT JOIN discounts d ON o.applied_discount_id = d.id 
      WHERE o.is_deleted = false
    `;
        const params = [];

        if (status && status !== 'all') {
            query += ' AND o.status = ?';
            params.push(status);
        }

        query += ' ORDER BY o.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const orders = await executeQuery(query, params);

        // Get order items for each order
        for (let order of orders) {
            const items = await executeQuery(`
        SELECT oi.*, ii.name, ii.sku, ii.image_url 
        FROM order_items oi 
        JOIN inventory_items ii ON oi.inventory_item_id = ii.id 
        WHERE oi.order_id = ?
      `, [order.id]);
            order.items = items;
        }

        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as total FROM orders WHERE is_deleted = false';
        if (status && status !== 'all') {
            countQuery += ' AND status = ?';
        }
        const countResult = await executeQuery(countQuery, status && status !== 'all' ? [status] : []);
        const total = countResult[0].total;

        res.json({
            orders,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single order
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const orderId = req.params.id;

        const orders = await executeQuery(`
      SELECT o.*, u.name as created_by_name, d.code as discount_code 
      FROM orders o 
      LEFT JOIN users u ON o.created_by_user_id = u.id 
      LEFT JOIN discounts d ON o.applied_discount_id = d.id 
      WHERE o.id = ? AND o.is_deleted = false
    `, [orderId]);

        if (orders.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        const order = orders[0];
        const items = await executeQuery(`
      SELECT oi.*, ii.name, ii.sku, ii.image_url 
      FROM order_items oi 
      JOIN inventory_items ii ON oi.inventory_item_id = ii.id 
      WHERE oi.order_id = ?
    `, [orderId]);

        order.items = items;
        res.json(order);
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create new order
router.post('/', authenticateToken, validateOrder, async (req, res) => {
    const connection = await require('../config/database').pool.getConnection();

    try {
        await connection.beginTransaction();

        const {
            customer_name,
            customer_contact,
            customer_address,
            customer_email,
            items,
            applied_discount_id = null
        } = req.body;

        // Validate all inventory items and calculate totals
        let subtotal = 0;
        const validatedItems = [];

        for (const item of items) {
            const inventoryItem = await connection.execute(
                'SELECT id, name, price, quantity FROM inventory_items WHERE id = ? AND is_deleted = false',
                [item.inventory_item_id]
            );

            if (inventoryItem[0].length === 0) {
                throw new Error(`Inventory item not found: ${item.inventory_item_id}`);
            }

            const itemData = inventoryItem[0][0];

            if (itemData.quantity < item.quantity) {
                throw new Error(`Insufficient stock for ${itemData.name}. Available: ${itemData.quantity}, Requested: ${item.quantity}`);
            }

            const itemTotal = itemData.price * item.quantity;
            subtotal += itemTotal;

            validatedItems.push({
                ...item,
                price_at_purchase: itemData.price,
                name: itemData.name
            });
        }

        // Apply discount if provided
        let discountAmount = 0;
        let total = subtotal;

        if (applied_discount_id) {
            const discount = await connection.execute(
                `SELECT * FROM discounts 
         WHERE id = ? AND is_active = true AND is_deleted = false 
         AND (min_spend IS NULL OR min_spend <= ?) 
         AND (min_items IS NULL OR min_items <= ?)`,
                [applied_discount_id, subtotal, items.length]
            );

            if (discount[0].length === 0) {
                throw new Error('Invalid or inapplicable discount');
            }

            const discountData = discount[0][0];

            if (discountData.type === 'Percentage') {
                discountAmount = subtotal * (discountData.value / 100);
            } else {
                discountAmount = Math.min(discountData.value, subtotal);
            }

            total = subtotal - discountAmount;

            // Update discount usage count
            await connection.execute(
                'UPDATE discounts SET used_count = used_count + 1 WHERE id = ?',
                [applied_discount_id]
            );
        }

        // Create order
        const orderId = uuidv4();
        await connection.execute(
            `INSERT INTO orders 
       (id, customer_name, customer_contact, customer_address, customer_email, 
        subtotal, discount_amount, total, created_by_user_id, applied_discount_id) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [orderId, customer_name, customer_contact, customer_address, customer_email,
                subtotal, discountAmount, total, req.user.id, applied_discount_id]
        );

        // Create order items and update inventory
        for (const item of validatedItems) {
            const orderItemId = uuidv4();

            await connection.execute(
                'INSERT INTO order_items (id, order_id, inventory_item_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?, ?)',
                [orderItemId, orderId, item.inventory_item_id, item.quantity, item.price_at_purchase]
            );

            // Update inventory quantity
            await connection.execute(
                'UPDATE inventory_items SET quantity = quantity - ? WHERE id = ?',
                [item.quantity, item.inventory_item_id]
            );

            // Log inventory movement
            const movementId = uuidv4();
            await connection.execute(
                `INSERT INTO inventory_movements 
         (id, inventory_item_id, user_id, related_order_id, type, quantity_change, reason) 
         VALUES (?, ?, ?, ?, 'StockOut', ?, 'Order fulfillment')`,
                [movementId, item.inventory_item_id, req.user.id, orderId, item.quantity]
            );
        }

        await connection.commit();

        // Fetch complete order data
        const newOrder = await executeQuery(`
      SELECT o.*, u.name as created_by_name 
      FROM orders o 
      LEFT JOIN users u ON o.created_by_user_id = u.id 
      WHERE o.id = ?
    `, [orderId]);

        const orderItems = await executeQuery(`
      SELECT oi.*, ii.name, ii.sku 
      FROM order_items oi 
      JOIN inventory_items ii ON oi.inventory_item_id = ii.id 
      WHERE oi.order_id = ?
    `, [orderId]);

        const orderData = { ...newOrder[0], items: orderItems };

        await sendOrderConfirmationEmail(orderData);

        res.status(201).json(orderData);

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
        await connection.rollback();
        console.error('Create order error:', error);
        res.status(400).json({ message: error.message || 'Failed to create order' });
    } finally {
        connection.release();
    }
});

// Update order status
router.put('/:id/status', authenticateToken, async (req, res) => {
    try {
        const orderId = req.params.id;
        const { status } = req.body;

        const validStatuses = ['Processing', 'Shipped', 'Delivered', 'Cancelled', 'Refunded'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Invalid order status' });
        }

        // Check if order exists
        const order = await executeQuery(
            'SELECT * FROM orders WHERE id = ? AND is_deleted = false',
            [orderId]
        );

        if (order.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        await executeQuery(
            'UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [status, orderId]
        );

        // If order is cancelled or refunded, restore inventory
        if (status === 'Cancelled' || status === 'Refunded') {
            const orderItems = await executeQuery(
                'SELECT inventory_item_id, quantity FROM order_items WHERE order_id = ?',
                [orderId]
            );

            for (const item of orderItems) {
                await executeQuery(
                    'UPDATE inventory_items SET quantity = quantity + ? WHERE id = ?',
                    [item.quantity, item.inventory_item_id]
                );

                // Log inventory movement for restoration
                const movementId = uuidv4();
                await executeQuery(
                    `INSERT INTO inventory_movements 
           (id, inventory_item_id, user_id, related_order_id, type, quantity_change, reason) 
           VALUES (?, ?, ?, ?, 'Return', ?, ?)`,
                    [movementId, item.inventory_item_id, req.user.id, orderId,
                        item.quantity, `Order ${status.toLowerCase()}`]
                );
            }
        }

        // After successful status update:
        await sendOrderStatusUpdateEmail(order, status);

        res.json({ message: 'Order status updated successfully' });
    } catch (error) {
        console.error('Update order status error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete order (soft delete)
router.delete('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const orderId = req.params.id;

        await executeQuery(
            'UPDATE orders SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [orderId]
        );

        res.json({ message: 'Order archived successfully' });
    } catch (error) {
        console.error('Delete order error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    const connection = await require('../config/database').pool.getConnection();

    try {
        await connection.beginTransaction();

        const orderId = req.params.id;

        // Delete order items first (due to foreign key constraints)
        await connection.execute('DELETE FROM order_items WHERE order_id = ?', [orderId]);

        // Delete order
        await connection.execute('DELETE FROM orders WHERE id = ?', [orderId]);

        await connection.commit();
        res.json({ message: 'Order permanently deleted' });
    } catch (error) {
        await connection.rollback();
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    } finally {
        connection.release();
    }
});

// Get order statistics
router.get('/stats/overview', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const { period = 'month' } = req.query;
        let dateFilter = '';

        switch (period) {
            case 'today':
                dateFilter = 'AND DATE(created_at) = CURDATE()';
                break;
            case 'week':
                dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
                break;
            case 'month':
                dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
                break;
            case 'year':
                dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 1 YEAR)';
                break;
        }

        const stats = await executeQuery(`
      SELECT 
        COUNT(*) as total_orders,
        SUM(total) as total_revenue,
        AVG(total) as average_order_value,
        SUM(CASE WHEN status = 'Delivered' THEN 1 ELSE 0 END) as completed_orders,
        SUM(CASE WHEN status = 'Processing' THEN 1 ELSE 0 END) as processing_orders
      FROM orders 
      WHERE is_deleted = false ${dateFilter}
    `);

        const statusDistribution = await executeQuery(`
      SELECT status, COUNT(*) as count 
      FROM orders 
      WHERE is_deleted = false ${dateFilter}
      GROUP BY status
    `);

        const recentOrders = await executeQuery(`
      SELECT id, customer_name, total, status, created_at 
      FROM orders 
      WHERE is_deleted = false 
      ORDER BY created_at DESC 
      LIMIT 10
    `);

        res.json({
            overview: stats[0],
            statusDistribution,
            recentOrders
        });
    } catch (error) {
        console.error('Get order stats error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;