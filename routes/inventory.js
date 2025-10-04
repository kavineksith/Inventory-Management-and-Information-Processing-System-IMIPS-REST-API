const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const { executeQuery } = require('../config/database');
const { authenticateToken, requireRole, trackActivity } = require('../middleware/auth');
const { validateInventoryItem } = require('../middleware/validation');
const { fileUploadSecurity } = require('../middleware/security');

// Configure multer for product images
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads/products');
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'product-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Get all inventory items
router.get('/', authenticateToken, trackActivity, async (req, res) => {
    try {
        const items = await executeQuery(`
      SELECT id, name, sku, quantity, threshold, category, price, image_url, 
             warranty_period_months, is_deleted, created_at, updated_at 
      FROM inventory_items 
      WHERE is_deleted = false 
      ORDER BY created_at DESC
    `);
        res.json(items);
    } catch (error) {
        console.error('Get inventory error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create inventory item
router.post('/', authenticateToken, upload.single('image'), fileUploadSecurity, validateInventoryItem, async (req, res) => {
    try {
        const {
            name,
            sku,
            quantity,
            threshold,
            category,
            price,
            warranty_period_months
        } = req.body;

        const itemId = uuidv4();
        let imageUrl = null;

        if (req.file) {
            imageUrl = `/uploads/products/${req.file.filename}`;
        }

        await executeQuery(
            `INSERT INTO inventory_items 
       (id, name, sku, quantity, threshold, category, price, image_url, warranty_period_months) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [itemId, name, sku, parseInt(quantity), parseInt(threshold), category,
                parseFloat(price), imageUrl, parseInt(warranty_period_months) || 0]
        );

        // Log inventory movement
        const movementId = uuidv4();
        await executeQuery(
            `INSERT INTO inventory_movements 
       (id, inventory_item_id, user_id, type, quantity_change, reason) 
       VALUES (?, ?, ?, 'StockIn', ?, 'Initial stock')`,
            [movementId, itemId, req.user.id, parseInt(quantity)]
        );

        const newItem = await executeQuery(
            'SELECT * FROM inventory_items WHERE id = ?',
            [itemId]
        );

        res.status(201).json(newItem[0]);
    } catch (error) {
        console.error('Create inventory error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update inventory item
router.put('/:id', authenticateToken, upload.single('image'), fileUploadSecurity, validateInventoryItem, async (req, res) => {
    try {
        const itemId = req.params.id;
        const {
            name,
            sku,
            quantity,
            threshold,
            category,
            price,
            warranty_period_months
        } = req.body;

        // Check if item exists and not deleted
        const existingItem = await executeQuery(
            'SELECT * FROM inventory_items WHERE id = ? AND is_deleted = false',
            [itemId]
        );

        if (existingItem.length === 0) {
            return res.status(404).json({ message: 'Inventory item not found' });
        }

        // Build update query
        const updates = [];
        const params = [];

        if (name) {
            updates.push('name = ?');
            params.push(name);
        }
        if (sku) {
            updates.push('sku = ?');
            params.push(sku);
        }
        if (quantity !== undefined) {
            // Log quantity change if different
            const oldQuantity = existingItem[0].quantity;
            const quantityChange = parseInt(quantity) - oldQuantity;

            if (quantityChange !== 0) {
                const movementId = uuidv4();
                await executeQuery(
                    `INSERT INTO inventory_movements 
           (id, inventory_item_id, user_id, type, quantity_change, reason) 
           VALUES (?, ?, ?, ?, ?, 'Manual adjustment')`,
                    [movementId, itemId, req.user.id,
                        quantityChange > 0 ? 'AdjustmentIn' : 'AdjustmentOut',
                        Math.abs(quantityChange)]
                );
            }

            updates.push('quantity = ?');
            params.push(parseInt(quantity));
        }
        if (threshold !== undefined) {
            updates.push('threshold = ?');
            params.push(parseInt(threshold));
        }
        if (category) {
            updates.push('category = ?');
            params.push(category);
        }
        if (price !== undefined) {
            updates.push('price = ?');
            params.push(parseFloat(price));
        }
        if (warranty_period_months !== undefined) {
            updates.push('warranty_period_months = ?');
            params.push(parseInt(warranty_period_months));
        }

        // Handle image upload
        if (req.file) {
            const imageUrl = `/uploads/products/${req.file.filename}`;
            updates.push('image_url = ?');
            params.push(imageUrl);

            // Delete old image if exists
            if (existingItem[0].image_url) {
                const oldPath = path.join(__dirname, '..', existingItem[0].image_url);
                try {
                    await fs.unlink(oldPath);
                } catch (error) {
                    console.warn('Could not delete old product image:', error);
                }
            }
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(itemId);

        await executeQuery(
            `UPDATE inventory_items SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const updatedItem = await executeQuery(
            'SELECT * FROM inventory_items WHERE id = ?',
            [itemId]
        );

        res.json(updatedItem[0]);
    } catch (error) {
        console.error('Update inventory error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete inventory item (soft delete)
router.delete('/:id', authenticateToken, requireRole(['Admin', 'Manager']), async (req, res) => {
    try {
        const itemId = req.params.id;

        await executeQuery(
            'UPDATE inventory_items SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [itemId]
        );

        res.json({ message: 'Item archived successfully' });
    } catch (error) {
        console.error('Delete inventory error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Permanent delete
router.delete('/:id/permanent', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const itemId = req.params.id;

        // Get item to delete associated image
        const item = await executeQuery(
            'SELECT image_url FROM inventory_items WHERE id = ?',
            [itemId]
        );

        if (item.length > 0 && item[0].image_url) {
            const imagePath = path.join(__dirname, '..', item[0].image_url);
            try {
                await fs.unlink(imagePath);
            } catch (error) {
                console.warn('Could not delete product image:', error);
            }
        }

        await executeQuery('DELETE FROM inventory_items WHERE id = ?', [itemId]);
        res.json({ message: 'Item permanently deleted' });
    } catch (error) {
        console.error('Permanent delete error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get inventory movements
router.get('/:id/movements', authenticateToken, async (req, res) => {
    try {
        const itemId = req.params.id;

        const movements = await executeQuery(`
      SELECT im.*, u.name as user_name 
      FROM inventory_movements im 
      JOIN users u ON im.user_id = u.id 
      WHERE im.inventory_item_id = ? 
      ORDER BY im.created_at DESC
    `, [itemId]);

        res.json(movements);
    } catch (error) {
        console.error('Get movements error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get low stock items
router.get('/alerts/low-stock', authenticateToken, async (req, res) => {
    try {
        const lowStockItems = await executeQuery(`
      SELECT id, name, sku, quantity, threshold, category 
      FROM inventory_items 
      WHERE quantity <= threshold AND is_deleted = false 
      ORDER BY quantity ASC
    `);
        res.json(lowStockItems);
    } catch (error) {
        console.error('Get low stock error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;