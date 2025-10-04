-- Password Reset Tokens Table
CREATE TABLE IF NOT EXISTS password_resets (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
);

-- Add cleanup for expired tokens (optional, can be handled by cron)
CREATE EVENT IF NOT EXISTS cleanup_expired_password_resets
ON SCHEDULE EVERY 1 HOUR
DO
  DELETE FROM password_resets WHERE expires_at < NOW();

-- Update user_sessions table to add missing columns if they don't exist
ALTER TABLE user_sessions 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) NULL AFTER user_id,
ADD COLUMN IF NOT EXISTS user_agent TEXT NULL AFTER ip_address,
ADD COLUMN IF NOT EXISTS last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP AFTER login_time;

-- Add index for active sessions
ALTER TABLE user_sessions 
ADD INDEX IF NOT EXISTS idx_active (logout_time);

-- Update users table to add password_changed_at if not exists
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP NULL AFTER last_activity;