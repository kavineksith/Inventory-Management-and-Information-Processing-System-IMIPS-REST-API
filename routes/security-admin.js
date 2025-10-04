const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../middleware/auth');
const {
    getBlockedIPs,
    unblockIP,
    blockIP
} = require('../middleware/pathSecurity');
const { executeQuery } = require('../config/database');
const { logSecurityEvent } = require('../middleware/security');

// Get all blocked IPs (Admin only)
router.get('/blocked-ips', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const blockedIPs = getBlockedIPs();

        res.json({
            total: blockedIPs.length,
            blocked: blockedIPs
        });
    } catch (error) {
        console.error('Get blocked IPs error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Unblock an IP (Admin only)
router.delete('/blocked-ips/:ip', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const ipToUnblock = req.params.ip;

        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
        if (!ipRegex.test(ipToUnblock)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        unblockIP(ipToUnblock);

        logSecurityEvent('IP_MANUALLY_UNBLOCKED', req, {
            unlockedIP: ipToUnblock,
            adminId: req.user.id
        });

        res.json({
            message: 'IP unblocked successfully',
            ip: ipToUnblock
        });
    } catch (error) {
        console.error('Unblock IP error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Manually block an IP (Admin only)
router.post('/block-ip', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const { ip, reason, duration } = req.body;

        if (!ip) {
            return res.status(400).json({ message: 'IP address is required' });
        }

        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        blockIP(ip, [{
            path: 'Manual block',
            timestamp: Date.now(),
            method: 'ADMIN',
            reason: reason || 'Manually blocked by administrator'
        }]);

        logSecurityEvent('IP_MANUALLY_BLOCKED', req, {
            blockedIP: ip,
            reason: reason || 'Manual block',
            adminId: req.user.id
        });

        res.json({
            message: 'IP blocked successfully',
            ip,
            reason: reason || 'Manually blocked'
        });
    } catch (error) {
        console.error('Block IP error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get security logs (Admin only)
router.get('/security-logs', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            event_type,
            start_date,
            end_date
        } = req.query;

        const offset = (page - 1) * limit;

        let query = `
            SELECT * FROM security_logs 
            WHERE 1=1
        `;
        const params = [];

        if (event_type) {
            query += ' AND event_type = ?';
            params.push(event_type);
        }

        if (start_date) {
            query += ' AND created_at >= ?';
            params.push(start_date);
        }

        if (end_date) {
            query += ' AND created_at <= ?';
            params.push(end_date);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const logs = await executeQuery(query, params);

        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM security_logs WHERE 1=1';
        const countParams = [];

        if (event_type) {
            countQuery += ' AND event_type = ?';
            countParams.push(event_type);
        }

        if (start_date) {
            countQuery += ' AND created_at >= ?';
            countParams.push(start_date);
        }

        if (end_date) {
            countQuery += ' AND created_at <= ?';
            countParams.push(end_date);
        }

        const countResult = await executeQuery(countQuery, countParams);
        const total = countResult[0].total;

        res.json({
            logs,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get security logs error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get security statistics (Admin only)
router.get('/security-stats', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const stats = await executeQuery(`
            SELECT 
                event_type,
                COUNT(*) as count,
                MAX(created_at) as last_occurrence
            FROM security_logs 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY event_type
            ORDER BY count DESC
        `);

        const recentBlocks = await executeQuery(`
            SELECT ip_address, COUNT(*) as attempts
            FROM security_logs 
            WHERE event_type IN ('IP_BLOCKED_PATH_ENUMERATION', 'SCANNER_DETECTED', 'SUSPICIOUS_PATH_DETECTED')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT 10
        `);

        const failedLogins = await executeQuery(`
            SELECT ip_address, COUNT(*) as attempts
            FROM security_logs 
            WHERE event_type IN ('LOGIN_FAILED_USER_NOT_FOUND', 'LOGIN_FAILED_INVALID_PASSWORD')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT 10
        `);

        const blockedIPs = getBlockedIPs();

        res.json({
            eventStats: stats,
            currentlyBlocked: blockedIPs.length,
            blockedIPs: blockedIPs.slice(0, 10),
            recentBlockedAttempts: recentBlocks,
            failedLoginAttempts: failedLogins
        });
    } catch (error) {
        console.error('Get security stats error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get recent suspicious activity (Admin only)
router.get('/suspicious-activity', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const suspicious = await executeQuery(`
            SELECT * FROM security_logs 
            WHERE event_type IN (
                'SUSPICIOUS_PATH_DETECTED',
                'SCANNER_DETECTED',
                'PATH_TRAVERSAL_ATTEMPT',
                'SQL_INJECTION_ATTEMPT',
                'XSS_ATTEMPT',
                'BLOCKED_IP_ATTEMPT',
                'UNAUTHORIZED_ACCESS_ATTEMPT'
            )
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ORDER BY created_at DESC
            LIMIT 100
        `);

        // Group by IP
        const byIP = {};
        suspicious.forEach(log => {
            if (!byIP[log.ip_address]) {
                byIP[log.ip_address] = {
                    ip: log.ip_address,
                    events: [],
                    count: 0
                };
            }
            byIP[log.ip_address].events.push({
                type: log.event_type,
                url: log.url,
                timestamp: log.created_at
            });
            byIP[log.ip_address].count++;
        });

        // Convert to array and sort
        const sortedActivity = Object.values(byIP)
            .sort((a, b) => b.count - a.count);

        res.json({
            total: suspicious.length,
            byIP: sortedActivity,
            recentEvents: suspicious.slice(0, 20)
        });
    } catch (error) {
        console.error('Get suspicious activity error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Export security events as CSV (Admin only)
router.get('/export-logs', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const { start_date, end_date } = req.query;

        let query = 'SELECT * FROM security_logs WHERE 1=1';
        const params = [];

        if (start_date) {
            query += ' AND created_at >= ?';
            params.push(start_date);
        }

        if (end_date) {
            query += ' AND created_at <= ?';
            params.push(end_date);
        }

        query += ' ORDER BY created_at DESC';

        const logs = await executeQuery(query, params);

        // Convert to CSV
        const csv = [
            'ID,Event Type,IP Address,URL,User ID,Created At,Details'
        ];

        logs.forEach(log => {
            csv.push([
                log.id,
                log.event_type,
                log.ip_address || '',
                log.url || '',
                log.user_id || '',
                log.created_at,
                (log.details || '').replace(/,/g, ';')
            ].join(','));
        });

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=security-logs-${Date.now()}.csv`);
        res.send(csv.join('\n'));

        logSecurityEvent('SECURITY_LOGS_EXPORTED', req, {
            adminId: req.user.id,
            recordCount: logs.length
        });
    } catch (error) {
        console.error('Export logs error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Clear old security logs (Admin only)
router.delete('/clear-old-logs', authenticateToken, requireRole(['Admin']), async (req, res) => {
    try {
        const { days = 90 } = req.body;

        if (days < 30) {
            return res.status(400).json({
                message: 'Cannot delete logs less than 30 days old'
            });
        }

        const result = await executeQuery(
            'DELETE FROM security_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
            [parseInt(days)]
        );

        logSecurityEvent('SECURITY_LOGS_CLEARED', req, {
            adminId: req.user.id,
            daysOld: days,
            deletedCount: result.affectedRows
        });

        res.json({
            message: 'Old security logs cleared',
            deletedCount: result.affectedRows,
            daysOld: days
        });
    } catch (error) {
        console.error('Clear logs error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;