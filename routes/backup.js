const express = require('express');
const router = express.Router();
const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { executeQuery, pool } = require('../config/database');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Ensure backup directory exists
const backupDir = path.join(__dirname, '../backups');
fs.ensureDirSync(backupDir);

// Create backup
router.post('/create', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const { include_data = true, include_schema = true } = req.body;
        const backupId = uuidv4();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `backup-${timestamp}-${backupId}.json`;
        const filepath = path.join(backupDir, filename);

        const backup = {
            metadata: {
                id: backupId,
                created_at: new Date().toISOString(),
                created_by: req.user.id,
                version: '1.0',
                includes: {
                    schema: include_schema,
                    data: include_data
                }
            },
            tables: {}
        };

        // Get database schema if requested
        if (include_schema) {
            const tables = await executeQuery(`
        SELECT TABLE_NAME as table_name 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_SCHEMA = ?
      `, [process.env.DB_NAME]);

            backup.schema = {};

            for (const table of tables) {
                const columns = await executeQuery(`
          SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, EXTRA
          FROM INFORMATION_SCHEMA.COLUMNS 
          WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
          ORDER BY ORDINAL_POSITION
        `, [process.env.DB_NAME, table.table_name]);

                backup.schema[table.table_name] = columns;
            }
        }

        // Get table data if requested
        if (include_data) {
            const tables = [
                'users', 'inventory_items', 'customer_inquiries', 'discounts',
                'orders', 'order_items', 'inventory_movements', 'user_sessions', 'emails'
            ];

            for (const tableName of tables) {
                try {
                    const data = await executeQuery(`SELECT * FROM ?? WHERE is_deleted = false`, [tableName]);
                    backup.tables[tableName] = data;
                } catch (error) {
                    // If table doesn't have is_deleted column, get all data
                    if (error.code === 'ER_BAD_FIELD_ERROR') {
                        const data = await executeQuery(`SELECT * FROM ??`, [tableName]);
                        backup.tables[tableName] = data;
                    } else {
                        throw error;
                    }
                }
            }
        }

        // Write backup to file
        await fs.writeJson(filepath, backup, { spaces: 2 });

        // Clean up old backups (keep last 30 days)
        await cleanupOldBackups();

        res.json({
            message: 'Backup created successfully',
            backup_id: backupId,
            filename: filename,
            filepath: filepath,
            size: (await fs.stat(filepath)).size,
            tables: Object.keys(backup.tables)
        });
    } catch (error) {
        console.error('Backup creation error:', error);
        res.status(500).json({ message: 'Failed to create backup: ' + error.message });
    }
});

// List backups
router.get('/list', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const files = await fs.readdir(backupDir);
        const backups = [];

        for (const file of files) {
            if (file.endsWith('.json')) {
                const filepath = path.join(backupDir, file);
                const stats = await fs.stat(filepath);

                try {
                    const backupData = await fs.readJson(filepath);
                    backups.push({
                        filename: file,
                        created_at: backupData.metadata.created_at,
                        created_by: backupData.metadata.created_by,
                        size: stats.size,
                        tables: Object.keys(backupData.tables || {}),
                        includes_schema: backupData.metadata.includes.schema,
                        includes_data: backupData.metadata.includes.data
                    });
                } catch (error) {
                    console.warn(`Invalid backup file: ${file}`, error);
                }
            }
        }

        // Sort by creation date (newest first)
        backups.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json(backups);
    } catch (error) {
        console.error('List backups error:', error);
        res.status(500).json({ message: 'Failed to list backups' });
    }
});

// Restore backup
router.post('/restore', authenticateToken, requireRole(['Admin']), async (req, res) => {
    const connection = await pool.getConnection();

    try {
        const { filename, restore_tables = [] } = req.body;

        if (!filename) {
            return res.status(400).json({ message: 'Backup filename is required' });
        }

        const filepath = path.join(backupDir, filename);

        if (!await fs.pathExists(filepath)) {
            return res.status(404).json({ message: 'Backup file not found' });
        }

        const backupData = await fs.readJson(filepath);
        await connection.beginTransaction();

        try {
            // If specific tables are provided, restore only those
            const tablesToRestore = restore_tables.length > 0
                ? restore_tables
                : Object.keys(backupData.tables);

            for (const tableName of tablesToRestore) {
                if (!backupData.tables[tableName]) {
                    console.warn(`Table ${tableName} not found in backup`);
                    continue;
                }

                // Clear existing data (be careful with this in production!)
                await connection.execute(`DELETE FROM ??`, [tableName]);

                // Insert backup data
                const rows = backupData.tables[tableName];
                if (rows.length > 0) {
                    const columns = Object.keys(rows[0]);
                    const placeholders = columns.map(() => '?').join(', ');
                    const query = `INSERT INTO ?? (${columns.map(col => `\`${col}\``).join(', ')}) VALUES (${placeholders})`;

                    for (const row of rows) {
                        const values = columns.map(col => row[col]);
                        await connection.execute(query, [tableName, ...values]);
                    }
                }

                console.log(`Restored ${rows.length} rows to ${tableName}`);
            }

            await connection.commit();
            res.json({
                message: 'Backup restored successfully',
                tables_restored: tablesToRestore
            });
        } catch (restoreError) {
            await connection.rollback();
            throw restoreError;
        }
    } catch (error) {
        console.error('Restore backup error:', error);
        res.status(500).json({ message: 'Failed to restore backup: ' + error.message });
    } finally {
        connection.release();
    }
});

// Download backup file
router.get('/download/:filename', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const filename = req.params.filename;

        // Security: Prevent path traversal
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({ message: 'Invalid filename' });
        }

        const filepath = path.join(backupDir, filename);

        if (!await fs.pathExists(filepath)) {
            return res.status(404).json({ message: 'Backup file not found' });
        }

        res.download(filepath, `backup-${Date.now()}.json`);
    } catch (error) {
        console.error('Download backup error:', error);
        res.status(500).json({ message: 'Failed to download backup' });
    }
});

// Delete backup
router.delete('/:filename', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const filename = req.params.filename;

        // Security: Prevent path traversal
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({ message: 'Invalid filename' });
        }

        const filepath = path.join(backupDir, filename);

        if (!await fs.pathExists(filepath)) {
            return res.status(404).json({ message: 'Backup file not found' });
        }

        await fs.unlink(filepath);
        res.json({ message: 'Backup deleted successfully' });
    } catch (error) {
        console.error('Delete backup error:', error);
        res.status(500).json({ message: 'Failed to delete backup' });
    }
});

// Get backup statistics
router.get('/stats', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const files = await fs.readdir(backupDir);
        const backupFiles = files.filter(file => file.endsWith('.json'));

        let totalSize = 0;
        let oldestBackup = null;
        let newestBackup = null;

        for (const file of backupFiles) {
            const filepath = path.join(backupDir, file);
            const stats = await fs.stat(filepath);
            totalSize += stats.size;

            if (!oldestBackup || stats.birthtime < oldestBackup.birthtime) {
                oldestBackup = stats;
            }
            if (!newestBackup || stats.birthtime > newestBackup.birthtime) {
                newestBackup = stats;
            }
        }

        res.json({
            total_backups: backupFiles.length,
            total_size: totalSize,
            total_size_mb: (totalSize / (1024 * 1024)).toFixed(2),
            oldest_backup: oldestBackup?.birthtime,
            newest_backup: newestBackup?.birthtime,
            backup_directory: backupDir
        });
    } catch (error) {
        console.error('Get backup stats error:', error);
        res.status(500).json({ message: 'Failed to get backup statistics' });
    }
});

// Clean up old backups (keep only last 30 days)
async function cleanupOldBackups() {
    try {
        const files = await fs.readdir(backupDir);
        const now = Date.now();
        const retentionPeriod = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

        for (const file of files) {
            if (file.endsWith('.json')) {
                const filepath = path.join(backupDir, file);
                const stats = await fs.stat(filepath);

                if (now - stats.birthtime.getTime() > retentionPeriod) {
                    await fs.unlink(filepath);
                    console.log(`Deleted old backup: ${file}`);
                }
            }
        }
    } catch (error) {
        console.error('Backup cleanup error:', error);
    }
}

module.exports = router;