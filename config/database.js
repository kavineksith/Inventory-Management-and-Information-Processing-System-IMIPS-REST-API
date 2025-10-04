const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// Validate database configuration
if (!process.env.DB_PASSWORD && process.env.NODE_ENV === 'production') {
  console.error('CRITICAL: DB_PASSWORD must be set in production!');
  process.exit(1);
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'imips',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  // Security: Use SSL in production
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: true
  } : false
});

// SQL injection protection - parameterized queries only
const executeQuery = async (query, params = []) => {
  const connection = await pool.getConnection();
  try {
    const [results] = await connection.execute(query, params);
    return results;
  } finally {
    connection.release();
  }
};

// Initialize database schema with enhanced security tables
const initializeDatabase = async () => {
  try {
    console.log('Initializing database schema...');

    // Users table with password change tracking
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('Admin', 'Manager', 'Staff') NOT NULL DEFAULT 'Staff',
                profile_picture_url VARCHAR(255) DEFAULT NULL,
                last_activity TIMESTAMP NULL,
                password_changed_at TIMESTAMP NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_role (role),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Enhanced user sessions table with IP and user agent tracking
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45) NULL,
                user_agent TEXT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                logout_time TIMESTAMP NULL,
                duration_minutes INTEGER DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user (user_id),
                INDEX idx_login (login_time),
                INDEX idx_active (logout_time)
            )
        `);

    // Security logs table for audit trail
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                event_type VARCHAR(100) NOT NULL,
                ip_address VARCHAR(45) NULL,
                user_agent TEXT NULL,
                url VARCHAR(500) NULL,
                user_id VARCHAR(255) NULL,
                details TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_event_type (event_type),
                INDEX idx_user (user_id),
                INDEX idx_created (created_at)
            )
        `);

    // Inventory items table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS inventory_items (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                sku VARCHAR(50) UNIQUE NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 0,
                threshold INTEGER NOT NULL DEFAULT 0,
                category VARCHAR(100) NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                image_url VARCHAR(255) DEFAULT NULL,
                warranty_period_months INTEGER DEFAULT 0,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_sku (sku),
                INDEX idx_category (category),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Customer inquiries table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS customer_inquiries (
                id VARCHAR(255) PRIMARY KEY,
                customer_name VARCHAR(255) NOT NULL,
                customer_email VARCHAR(255) NOT NULL,
                inquiry_details TEXT NOT NULL,
                status ENUM('Pending', 'In Progress', 'Completed') NOT NULL DEFAULT 'Pending',
                assigned_user_id VARCHAR(255) DEFAULT NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (assigned_user_id) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_status (status),
                INDEX idx_email (customer_email),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Discounts table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS discounts (
                id VARCHAR(255) PRIMARY KEY,
                code VARCHAR(50) UNIQUE NOT NULL,
                description TEXT NOT NULL,
                type ENUM('Percentage', 'FixedAmount') NOT NULL,
                value DECIMAL(10,2) NOT NULL,
                min_spend DECIMAL(10,2) DEFAULT NULL,
                min_items INTEGER DEFAULT NULL,
                is_active BOOLEAN NOT NULL DEFAULT true,
                used_count INTEGER NOT NULL DEFAULT 0,
                created_by_user_id VARCHAR(255) NOT NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
                INDEX idx_code (code),
                INDEX idx_active (is_active),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Orders table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS orders (
                id VARCHAR(255) PRIMARY KEY,
                customer_name VARCHAR(255) NOT NULL,
                customer_contact VARCHAR(50) NOT NULL,
                customer_address TEXT NOT NULL,
                customer_email VARCHAR(255) NOT NULL,
                subtotal DECIMAL(10,2) NOT NULL,
                discount_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                total DECIMAL(10,2) NOT NULL,
                status ENUM('Processing', 'Shipped', 'Delivered', 'Cancelled', 'Refunded') NOT NULL DEFAULT 'Processing',
                created_by_user_id VARCHAR(255) NOT NULL,
                applied_discount_id VARCHAR(255) DEFAULT NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
                FOREIGN KEY (applied_discount_id) REFERENCES discounts(id) ON DELETE SET NULL,
                INDEX idx_status (status),
                INDEX idx_email (customer_email),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Order items table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS order_items (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                order_id VARCHAR(255) NOT NULL,
                inventory_item_id VARCHAR(255) NOT NULL,
                quantity INTEGER NOT NULL,
                price_at_purchase DECIMAL(10,2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (inventory_item_id) REFERENCES inventory_items(id) ON DELETE RESTRICT,
                INDEX idx_order (order_id),
                INDEX idx_item (inventory_item_id)
            )
        `);

    // Inventory movements table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS inventory_movements (
                id VARCHAR(255) PRIMARY KEY,
                inventory_item_id VARCHAR(255) NOT NULL,
                user_id VARCHAR(255) NOT NULL,
                related_order_id VARCHAR(255) DEFAULT NULL,
                type ENUM('StockIn', 'StockOut', 'AdjustmentIn', 'AdjustmentOut', 'Damage', 'Expired', 'Return') NOT NULL,
                quantity_change INTEGER NOT NULL,
                reason TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (inventory_item_id) REFERENCES inventory_items(id) ON DELETE RESTRICT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
                FOREIGN KEY (related_order_id) REFERENCES orders(id) ON DELETE SET NULL,
                INDEX idx_item (inventory_item_id),
                INDEX idx_type (type),
                INDEX idx_created (created_at)
            )
        `);

    // Emails table
    await executeQuery(`
            CREATE TABLE IF NOT EXISTS emails (
                id VARCHAR(255) PRIMARY KEY,
                sent_by_user_id VARCHAR(255) NOT NULL,
                recipient TEXT NOT NULL,
                subject VARCHAR(255) NOT NULL,
                body TEXT NOT NULL,
                attachment_path VARCHAR(255) DEFAULT NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sent_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
                INDEX idx_recipient (recipient(255)),
                INDEX idx_created (created_at),
                INDEX idx_deleted (is_deleted)
            )
        `);

    // Newsletter tracking table
    await executeQuery(`
        CREATE TABLE IF NOT EXISTS newsletters (
          id VARCHAR(255) PRIMARY KEY,
          subject VARCHAR(200) NOT NULL,
          html_content LONGTEXT NOT NULL,
          recipient_group ENUM('all_customers', 'recent_customers', 'inquiry_customers', 'custom') NOT NULL,
          total_recipients INT NOT NULL DEFAULT 0,
          success_count INT NOT NULL DEFAULT 0,
          fail_count INT NOT NULL DEFAULT 0,
          failed_emails TEXT NULL,
          status ENUM('sending', 'completed', 'failed') NOT NULL DEFAULT 'sending',
          sent_by_user_id VARCHAR(255) NOT NULL,
          error_message TEXT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          completed_at TIMESTAMP NULL,
          FOREIGN KEY (sent_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
          INDEX idx_status (status),
          INDEX idx_created (created_at),
          INDEX idx_sent_by (sent_by_user_id)
        )
        `);
    // Inquiry responses tracking table
    await executeQuery(`
      CREATE TABLE IF NOT EXISTS inquiry_responses (
    id VARCHAR(255) PRIMARY KEY,
    inquiry_id VARCHAR(255) NOT NULL,
    response_message TEXT NOT NULL,
    responded_by_user_id VARCHAR(255) NOT NULL,
    has_attachments BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inquiry_id) REFERENCES customer_inquiries(id) ON DELETE CASCADE,
    FOREIGN KEY (responded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    INDEX idx_inquiry (inquiry_id),
    INDEX idx_created (created_at)
)
      `);

    // Newsletter subscriptions table
    await executeQuery(`
      CREATE TABLE IF NOT EXISTS newsletter_subscriptions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NULL,
    subscribed BOOLEAN NOT NULL DEFAULT true,
    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unsubscribed_at TIMESTAMP NULL,
    source ENUM('order', 'inquiry', 'manual') NOT NULL DEFAULT 'manual',
    INDEX idx_email (email),
    INDEX idx_subscribed (subscribed)
)
      `);

    // Create default admin user with secure random password
    const adminExists = await executeQuery(
      'SELECT id FROM users WHERE email = ?',
      ['admin@imips.com']
    );

    if (adminExists.length === 0) {
      const bcrypt = require('bcryptjs');

      // Generate secure random password
      const defaultPassword = crypto.randomBytes(16).toString('hex');
      const adminPasswordHash = await bcrypt.hash(defaultPassword, 12);
      const adminId = uuidv4();

      await executeQuery(
        'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [adminId, 'System Administrator', 'admin@imips.com', adminPasswordHash, 'Admin']
      );

      console.log('\n' + '='.repeat(60));
      console.log('IMPORTANT: Default admin account created!');
      console.log('Email: admin@imips.com');
      console.log('Password:', defaultPassword);
      console.log('CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!');
      console.log('='.repeat(60) + '\n');

      // In production, you might want to send this via secure channel
      if (process.env.NODE_ENV === 'production') {
        // Log to secure file or send to admin email
        const fs = require('fs-extra');
        await fs.writeFile(
          './ADMIN_CREDENTIALS.txt',
          `Admin Email: admin@imips.com\nAdmin Password: ${defaultPassword}\n\nDELETE THIS FILE AFTER READING!`,
          { mode: 0o600 }
        );
      }
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
};

// Health check function
const checkDatabaseHealth = async () => {
  try {
    await executeQuery('SELECT 1');
    return { healthy: true, message: 'Database connection OK' };
  } catch (error) {
    return { healthy: false, message: error.message };
  }
};

module.exports = {
  pool,
  executeQuery,
  initializeDatabase,
  checkDatabaseHealth
};