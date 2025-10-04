-- Newsletter tracking table
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
);

-- Inquiry responses tracking table
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
);

-- Newsletter subscription table (optional - for future use)
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
);

-- Create upload directories function (for documentation)
-- Run these commands manually:
-- mkdir -p uploads/newsletters
-- mkdir -p uploads/inquiry-responses
-- chmod 750 uploads/newsletters
-- chmod 750 uploads/inquiry-responses