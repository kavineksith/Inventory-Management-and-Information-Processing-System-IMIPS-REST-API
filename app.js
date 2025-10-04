const express = require('express');
const path = require('path');
const fs = require('fs-extra');
require('dotenv').config();

// Validate critical environment variables
const requiredEnvVars = ['JWT_SECRET', 'ENCRYPTION_KEY', 'DB_PASSWORD'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0 && process.env.NODE_ENV === 'production') {
    console.error('CRITICAL: Missing required environment variables:', missingEnvVars.join(', '));
    console.error('Application cannot start in production without these variables.');
    process.exit(1);
}

// Import configurations and middleware
const { initializeDatabase, checkDatabaseHealth } = require('./config/database');
const { 
    securityMiddleware, 
    preventPathTraversal, 
    xssProtection 
} = require('./middleware/security');
const {
    preventPathEnumeration,
    detectScanningPatterns,
    detectScannerUserAgents,
    restrictMethods,
    handleAPI404,
    handle404
} = require('./middleware/pathSecurity');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const inventoryRoutes = require('./routes/inventory');
const orderRoutes = require('./routes/orders');
const inquiryRoutes = require('./routes/inquiries');
const discountRoutes = require('./routes/discounts');
const emailRoutes = require('./routes/emails');
const backupRoutes = require('./routes/backup');
const securityAdminRoutes = require('./routes/security-admin');
const newsletterRoutes = require('./routes/newsletter');
const newsletterSubscriptionRoutes = require('./routes/newsletter-subscription');

const app = express();
const PORT = process.env.PORT || 5000;

// Disable X-Powered-By header
app.disable('x-powered-by');

// Trust proxy if behind reverse proxy (nginx, load balancer, etc.)
if (process.env.TRUST_PROXY === 'true') {
    app.set('trust proxy', 1);
}

// Ensure upload directories exist
async function initializeDirectories() {
    const directories = [
        path.join(__dirname, 'uploads/profiles'),
        path.join(__dirname, 'uploads/products'),
        path.join(__dirname, 'uploads/attachments'),
        path.join(__dirname, 'backups'),
        path.join(__dirname, 'logs')
    ];

    for (const dir of directories) {
        await fs.ensureDir(dir);
        // Set restrictive permissions
        if (process.platform !== 'win32') {
            await fs.chmod(dir, 0o750);
        }
    }
}

// Setup logging
function setupLogging() {
    const winston = require('winston');
    
    const logger = winston.createLogger({
        level: process.env.LOG_LEVEL || 'info',
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
        ),
        transports: [
            new winston.transports.File({ 
                filename: path.join(__dirname, 'logs/error.log'), 
                level: 'error' 
            }),
            new winston.transports.File({ 
                filename: path.join(__dirname, 'logs/combined.log') 
            })
        ]
    });

    if (process.env.NODE_ENV !== 'production') {
        logger.add(new winston.transports.Console({
            format: winston.format.simple()
        }));
    }

    return logger;
}

// Application initialization
async function initializeApp() {
    try {
        console.log('Starting IMIPS application...');
        console.log('Environment:', process.env.NODE_ENV || 'development');

        // Initialize directories
        await initializeDirectories();

        // Setup logging
        const logger = setupLogging();
        app.locals.logger = logger;

        // Initialize database
        await initializeDatabase();

        // Security middleware (must be first)
        securityMiddleware(app);

        // Path enumeration and scanning detection
        app.use(restrictMethods);
        app.use(preventPathEnumeration);
        app.use(detectScanningPatterns);
        app.use(detectScannerUserAgents);

        // Body parsing middleware with size limits
        app.use(express.json({ 
            limit: '10mb',
            verify: (req, res, buf) => {
                req.rawBody = buf.toString('utf8');
            }
        }));
        app.use(express.urlencoded({ 
            extended: true, 
            limit: '10mb' 
        }));

        // Security middleware
        app.use(preventPathTraversal);
        app.use(xssProtection);

        // Request logging middleware
        app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                const duration = Date.now() - start;
                logger.info({
                    method: req.method,
                    url: req.originalUrl,
                    status: res.statusCode,
                    duration: `${duration}ms`,
                    ip: req.ip,
                    userAgent: req.headers['user-agent']
                });
            });
            next();
        });

        // Static file serving with security headers
        app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
            setHeaders: (res, filePath) => {
                res.set('X-Content-Type-Options', 'nosniff');
                res.set('X-Frame-Options', 'DENY');
                res.set('Cache-Control', 'private, max-age=3600');
            },
            dotfiles: 'deny'
        }));

        // API routes
        app.use('/api/auth', authRoutes);
        app.use('/api/users', userRoutes);
        app.use('/api/inventory', inventoryRoutes);
        app.use('/api/orders', orderRoutes);
        app.use('/api/inquiries', inquiryRoutes);
        app.use('/api/discounts', discountRoutes);
        app.use('/api/emails', emailRoutes);
        app.use('/api/backup', backupRoutes);
        app.use('/api/security', securityAdminRoutes);
        app.use('/api/newsletter', newsletterRoutes);
        app.use('/api/newsletter-subscriptions', newsletterSubscriptionRoutes);

        // Health check endpoint
        app.get('/api/health', async (req, res) => {
            const dbHealth = await checkDatabaseHealth();
            
            res.status(dbHealth.healthy ? 200 : 503).json({
                status: dbHealth.healthy ? 'OK' : 'DEGRADED',
                timestamp: new Date().toISOString(),
                environment: process.env.NODE_ENV || 'development',
                database: dbHealth,
                uptime: process.uptime()
            });
        });

        // API version endpoint
        app.get('/api/version', (req, res) => {
            res.json({
                version: '1.0.0',
                name: 'IMIPS Backend',
                environment: process.env.NODE_ENV || 'development'
            });
        });

        // 404 handler for API routes
        //app.use('/api/*', handleAPI404);

        // 404 handler for all other routes
        //app.use('/*', handle404);

        // Global error handler
        app.use((error, req, res, next) => {
            logger.error('Global error handler:', {
                error: error.message,
                stack: error.stack,
                url: req.originalUrl,
                method: req.method
            });

            // Don't leak error details in production
            if (process.env.NODE_ENV === 'production') {
                return res.status(500).json({ 
                    message: 'Internal server error',
                    requestId: req.id 
                });
            }

            res.status(error.status || 500).json({
                message: error.message || 'Internal server error',
                stack: error.stack
            });
        });

        // Start server
        const server = app.listen(PORT, () => {
            console.log(`✓ IMIPS server running on port ${PORT}`);
            console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`✓ Database: Connected`);
            console.log(`✓ Security: Enhanced`);
            if (process.env.NODE_ENV === 'production') {
                console.log('✓ HTTPS: Enforced');
            }
            console.log('\nServer is ready to accept connections\n');
        });

        // Graceful shutdown
        const gracefulShutdown = async (signal) => {
            console.log(`\n${signal} received. Starting graceful shutdown...`);
            
            server.close(async () => {
                console.log('HTTP server closed');
                
                try {
                    // Close database connections
                    await require('./config/database').pool.end();
                    console.log('Database connections closed');
                    
                    console.log('Graceful shutdown completed');
                    process.exit(0);
                } catch (error) {
                    console.error('Error during shutdown:', error);
                    process.exit(1);
                }
            });

            // Force shutdown after 30 seconds
            setTimeout(() => {
                console.error('Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    } catch (error) {
        console.error('Failed to initialize application:', error);
        process.exit(1);
    }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Start the application
initializeApp();

module.exports = app;