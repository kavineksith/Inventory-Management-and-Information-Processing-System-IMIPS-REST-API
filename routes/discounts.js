const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, trackActivity } = require('../middleware/auth');
const { validateDiscount } = require('../middleware/validation');

// Get all discounts
router.get('/', authenticateToken, requireRole(['Admin', 'Manager']), trackActivity, async (req, res) => {
    try {
        const { is_active, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = `
      SELECT d.*, u.name as created_by_name 
      FROM discounts d 
      JOIN users u ON d.created_by_user_id = u.id 
      WHERE d.is_deleted = false
    `;
        const params = [];

        if (is_active !== undefined) {
            query += ' AND d.is_active = ?';
            params.push(is_active === 'true');
        }

        query += ' ORDER BY d.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const discounts = await executeQuery(query, params);

        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as total FROM discounts WHERE is_deleted = false';
        const countParams = [];

        if (is_active !== undefined) {
            countQuery += ' AND is_active = ?';
            countParams.push(is_active === 'true');
        }

        const countResult = await executeQuery(countQuery, countParams);
        const total = countResult[0].total;

        res.json({
            discounts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get discounts error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single discount
router.get('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const discountId = req.params.id;

        const discounts = await executeQuery(`
      SELECT d.*, u.name as created_by_name 
      FROM discounts d 
      JOIN users u ON d.created_by_user_id = u.id 
      WHERE d.id = ? AND d.is_deleted = false
    `, [discountId]);

        if (discounts.length === 0) {
            return res.status(404).json({ message: 'Discount not found' });
        }

        res.json(discounts[0]);
    } catch (error) {
        console.error('Get discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Validate discount code
router.post('/validate', authenticateToken, async (req, res) => {
    try {
        const { code, subtotal = 0, item_count = 0 } = req.body;

        if (!code) {
            return res.status(400).json({ message: 'Discount code is required' });
        }

        const discount = await executeQuery(`
      SELECT * FROM discounts 
      WHERE code = ? AND is_active = true AND is_deleted = false 
      AND (min_spend IS NULL OR min_spend <= ?) 
      AND (min_items IS NULL OR min_items <= ?)
    `, [code, parseFloat(subtotal), parseInt(item_count)]);

        if (discount.length === 0) {
            return res.status(404).json({ message: 'Invalid or inapplicable discount code' });
        }

        const discountData = discount[0];
        let discount_amount = 0;

        if (discountData.type === 'Percentage') {
            discount_amount = subtotal * (discountData.value / 100);
        } else {
            discount_amount = Math.min(discountData.value, subtotal);
        }

        res.json({
            valid: true,
            discount: discountData,
            discount_amount,
            final_amount: subtotal - discount_amount
        });
    } catch (error) {
        console.error('Validate discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create new discount
router.post('/', authenticateToken, requireRole(['Admin', 'Manager']), validateDiscount, async (req, res) => {
    try {
        const {
            code,
            description,
            type,
            value,
            min_spend,
            min_items
        } = req.body;

        const discountId = uuidv4();

        await executeQuery(
            `INSERT INTO discounts 
       (id, code, description, type, value, min_spend, min_items, created_by_user_id) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [discountId, code, description, type, parseFloat(value),
                min_spend ? parseFloat(min_spend) : null,
                min_items ? parseInt(min_items) : null,
                req.user.id]
        );

        const newDiscount = await executeQuery(`
      SELECT d.*, u.name as created_by_name 
      FROM discounts d 
      JOIN users u ON d.created_by_user_id = u.id 
      WHERE d.id = ?
    `, [discountId]);

        res.status(201).json(newDiscount[0]);
    } catch (error) {
        console.error('Create discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update discount
router.put('/:id', authenticateToken, requireRole(['Admin', 'Manager']), validateDiscount, async (req, res) => {
    try {
        const discountId = req.params.id;
        const {
            code,
            description,
            type,
            value,
            min_spend,
            min_items,
            is_active
        } = req.body;

        // Check if discount exists
        const existingDiscount = await executeQuery(
            'SELECT * FROM discounts WHERE id = ? AND is_deleted = false',
            [discountId]
        );

        if (existingDiscount.length === 0) {
            return res.status(404).json({ message: 'Discount not found' });
        }

        // Build update query
        const updates = [];
        const params = [];

        if (code) {
            updates.push('code = ?');
            params.push(code);
        }
        if (description) {
            updates.push('description = ?');
            params.push(description);
        }
        if (type) {
            updates.push('type = ?');
            params.push(type);
        }
        if (value !== undefined) {
            updates.push('value = ?');
            params.push(parseFloat(value));
        }
        if (min_spend !== undefined) {
            updates.push('min_spend = ?');
            params.push(min_spend ? parseFloat(min_spend) : null);
        }
        if (min_items !== undefined) {
            updates.push('min_items = ?');
            params.push(min_items ? parseInt(min_items) : null);
        }
        if (is_active !== undefined) {
            updates.push('is_active = ?');
            params.push(is_active);
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(discountId);

        await executeQuery(
            `UPDATE discounts SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const updatedDiscount = await executeQuery(`
      SELECT d.*, u.name as created_by_name 
      FROM discounts d 
      JOIN users u ON d.created_by_user_id = u.id 
      WHERE d.id = ?
    `, [discountId]);

        res.json(updatedDiscount[0]);
    } catch (error) {
        console.error('Update discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Toggle discount active status
router.patch('/:id/toggle', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const discountId = req.params.id;

        const result = await executeQuery(
            'UPDATE discounts SET is_active = NOT is_active, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_deleted = false',
            [discountId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Discount not found' });
        }

        const updatedDiscount = await executeQuery(
            'SELECT * FROM discounts WHERE id = ?',
            [discountId]
        );

        res.json(updatedDiscount[0]);
    } catch (error) {
        console.error('Toggle discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete discount (soft delete)
router.delete('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const discountId = req.params.id;

        await executeQuery(
            'UPDATE discounts SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [discountId]
        );

        res.json({ message: 'Discount archived successfully' });
    } catch (error) {
        console.error('Delete discount error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const discountId = req.params.id;

        await executeQuery('DELETE FROM discounts WHERE id = ?', [discountId]);
        res.json({ message: 'Discount permanently deleted' });
    } catch (error) {
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get discount statistics
router.get('/stats/overview', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const stats = await executeQuery(`
      SELECT 
        COUNT(*) as total_discounts,
        SUM(CASE WHEN is_active = true THEN 1 ELSE 0 END) as active_discounts,
        SUM(used_count) as total_uses,
        SUM(CASE WHEN type = 'Percentage' THEN 1 ELSE 0 END) as percentage_discounts,
        SUM(CASE WHEN type = 'FixedAmount' THEN 1 ELSE 0 END) as fixed_discounts
      FROM discounts 
      WHERE is_deleted = false
    `);

        const topDiscounts = await executeQuery(`
      SELECT d.code, d.description, d.used_count, d.type, d.value 
      FROM discounts d 
      WHERE d.is_deleted = false 
      ORDER BY d.used_count DESC 
      LIMIT 10
    `);

        const recentDiscounts = await executeQuery(`
      SELECT d.*, u.name as created_by_name 
      FROM discounts d 
      JOIN users u ON d.created_by_user_id = u.id 
      WHERE d.is_deleted = false 
      ORDER BY d.created_at DESC 
      LIMIT 10
    `);

        res.json({
            overview: stats[0],
            topDiscounts,
            recentDiscounts
        });
    } catch (error) {
        console.error('Get discount stats error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;