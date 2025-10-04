# IMIPS Backend - Production Deployment Guide

## 🔒 Pre-Deployment Security Checklist

### Critical (Must Complete Before Deployment)

- [ ] **Generate secure cryptographic keys**
  ```bash
  npm run generate-keys
  ```

- [ ] **Set strong environment variables**
  - [ ] `JWT_SECRET` - Minimum 128 characters (64 bytes hex)
  - [ ] `ENCRYPTION_KEY` - Minimum 64 characters (32 bytes hex)
  - [ ] `DB_PASSWORD` - Strong, unique password (32+ characters)
  - [ ] All placeholder values replaced

- [ ] **Configure CORS properly**
  - [ ] Set `ALLOWED_ORIGINS` to only your frontend domains
  - [ ] No wildcards (*) in production

- [ ] **Database security**
  - [ ] Create dedicated database user (not root)
  - [ ] Grant minimum required privileges
  - [ ] Enable SSL/TLS connections
  - [ ] Set strong database password

- [ ] **File permissions**
  ```bash
  chmod 600 .env
  chmod 750 uploads/
  chmod 750 backups/
  chmod 750 logs/
  ```

- [ ] **Change default admin password**
  - Log in with generated credentials
  - Change password immediately
  - Use password manager

- [ ] **SSL/TLS Configuration**
  - [ ] Valid SSL certificate installed
  - [ ] HTTPS enforced (app handles redirect)
  - [ ] HTTP to HTTPS redirect at reverse proxy

- [ ] **Environment variables set**
  ```bash
  export NODE_ENV=production
  ```

### High Priority

- [ ] **Configure SMTP for emails**
  - Use app-specific passwords for Gmail
  - Test email delivery

- [ ] **Set up reverse proxy (Nginx/Apache)**
  - Configure SSL termination
  - Set proper headers
  - Enable compression

- [ ] **Configure firewall**
  ```bash
  # Example: UFW on Ubuntu
  ufw allow 22/tcp    # SSH
  ufw allow 80/tcp    # HTTP
  ufw allow 443/tcp   # HTTPS
  ufw enable
  ```

- [ ] **Database backups**
  - Set up automated daily backups
  - Test restore procedure
  - Store backups securely offsite

- [ ] **Application monitoring**
  - Set up logging aggregation
  - Configure error alerting
  - Monitor system resources

- [ ] **Security headers verified**
  - Test with securityheaders.com
  - Verify CSP policies

## 📦 Installation Steps

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js (v16 or higher)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install MySQL
sudo apt install -y mysql-server

# Install PM2 for process management
sudo npm install -g pm2
```

### 2. MySQL Database Setup

```bash
# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -u root -p
```

```sql
CREATE DATABASE imips CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'imips_user'@'localhost' IDENTIFIED BY 'YOUR_SECURE_PASSWORD';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER 
ON imips.* TO 'imips_user'@'localhost';

FLUSH PRIVILEGES;
EXIT;
```

### 3. Application Setup

```bash
# Clone or upload your application
cd /var/www
sudo mkdir imips-backend
sudo chown $USER:$USER imips-backend
cd imips-backend

# Upload files and install dependencies
npm install --production

# Generate security keys
npm run generate-keys

# Copy and configure environment
cp .env.example .env
nano .env  # Edit with your values

# Run database migrations
mysql -u imips_user -p imips < migrations/001_password_resets.sql

# Initialize application (creates admin user)
npm start
# Note the generated admin password!
# Stop with Ctrl+C
```

### 4. PM2 Process Management

```bash
# Start application with PM2
pm2 start app.js --name imips-backend

# Configure auto-start on reboot
pm2 startup
pm2 save

# Monitor application
pm2 status
pm2 logs imips-backend
pm2 monit
```

### 5. Nginx Reverse Proxy Configuration

```bash
sudo nano /etc/nginx/sites-available/imips-backend
```

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    client_max_body_size 10M;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable site and restart Nginx
sudo ln -s /etc/nginx/sites-available/imips-backend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 🔐 Post-Deployment Security Hardening

### 1. Disable Root Login
```bash
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
sudo systemctl restart sshd
```

### 2. Set Up Fail2Ban
```bash
sudo apt install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. Enable Automatic Security Updates
```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 4. Configure Log Rotation
```bash
sudo nano /etc/logrotate.d/imips
```

```
/var/www/imips-backend/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
}
```

### 5. Set Up Monitoring & Alerts

```bash
# PM2 Monitoring
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7

# System monitoring
sudo apt install htop iotop nethogs
```

## 🧪 Testing Production Setup

### 1. Health Check
```bash
curl https://api.yourdomain.com/api/health
```

### 2. Security Headers
```bash
curl -I https://api.yourdomain.com/api/health
```

### 3. SSL Certificate
```bash
openssl s_client -connect api.yourdomain.com:443 -servername api.yourdomain.com
```

### 4. Rate Limiting
```bash
# Should be blocked after 5 attempts
for i in {1..10}; do curl -X POST https://api.yourdomain.com/api/auth/login; done
```

### 5. Authentication Flow
- Test login with admin account
- Change admin password
- Create test user accounts
- Test all role permissions

## 📊 Monitoring & Maintenance

### Daily Tasks
- Check PM2 status: `pm2 status`
- Review error logs: `pm2 logs imips-backend --err --lines 50`
- Monitor disk space: `df -h`

### Weekly Tasks
- Review security logs
- Check database size and performance
- Verify backup completion
- Update dependencies (security patches)

### Monthly Tasks
- Review user activity logs
- Audit user permissions
- Test backup restore procedure
- Security vulnerability scan
- Update SSL certificates (if needed)

## 🚨 Incident Response

### Application Crashes
```bash
pm2 restart imips-backend
pm2 logs imips-backend --lines 100
```

### Database Issues
```bash
# Check MySQL status
sudo systemctl status mysql

# Check MySQL logs
sudo tail -f /var/log/mysql/error.log

# Restart MySQL
sudo systemctl restart mysql
```

### High CPU/Memory Usage
```bash
pm2 monit
htop
# Restart application if needed
pm2 restart imips-backend
```

### Security Breach Suspected
1. Immediately change all passwords
2. Review security logs
3. Check for unauthorized access
4. Invalidate all active sessions
5. Restore from clean backup if needed

## 📝 Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `NODE_ENV` | Yes | Environment mode | `production` |
| `PORT` | Yes | Application port | `5000` |
| `DB_HOST` | Yes | Database host | `localhost` |
| `DB_USER` | Yes | Database user | `imips_user` |
| `DB_PASSWORD` | Yes | Database password | `secure_password` |
| `DB_NAME` | Yes | Database name | `imips` |
| `JWT_SECRET` | Yes | JWT signing key | `64-byte-hex-string` |
| `JWT_EXPIRES_IN` | No | Token expiration | `24h` |
| `ENCRYPTION_KEY` | Yes | Data encryption key | `32-byte-hex-string` |
| `ALLOWED_ORIGINS` | Yes | CORS origins | `https://app.com` |
| `FRONTEND_URL` | Yes | Frontend URL | `https://app.com` |
| `SMTP_HOST` | Yes | Email server | `smtp.gmail.com` |
| `SMTP_PORT` | Yes | Email port | `587` |
| `SMTP_USER` | Yes | Email username | `user@gmail.com` |
| `SMTP_PASS` | Yes | Email password | `app-password` |
| `TRUST_PROXY` | No | Behind proxy | `true` |
| `LOG_SECURITY_TO_DB` | No | Log security events | `true` |
| `LOG_LEVEL` | No | Logging level | `info` |

## 🔄 Update & Rollback Procedures

### Updating the Application

```bash
# 1. Backup current version
cd /var/www/imips-backend
tar -czf ../imips-backup-$(date +%Y%m%d-%H%M%S).tar.gz .

# 2. Backup database
mysqldump -u imips_user -p imips > ../imips-db-$(date +%Y%m%d-%H%M%S).sql

# 3. Update code
git pull origin main
# or upload new files

# 4. Update dependencies
npm install --production

# 5. Run migrations if any
mysql -u imips_user -p imips < migrations/new_migration.sql

# 6. Restart application
pm2 restart imips-backend

# 7. Verify health
curl https://api.yourdomain.com/api/health

# 8. Monitor logs
pm2 logs imips-backend --lines 50
```

### Rolling Back

```bash
# 1. Stop application
pm2 stop imips-backend

# 2. Restore code
cd /var/www
tar -xzf imips-backup-TIMESTAMP.tar.gz -C imips-backend/

# 3. Restore database if needed
mysql -u imips_user -p imips < imips-db-TIMESTAMP.sql

# 4. Restart application
pm2 restart imips-backend

# 5. Verify
curl https://api.yourdomain.com/api/health
```

## 📞 Support & Troubleshooting

### Common Issues

**Issue: Application won't start**
```bash
# Check logs
pm2 logs imips-backend --err

# Common causes:
# - Missing environment variables
# - Database connection failure
# - Port already in use
# - File permission issues
```

**Issue: Database connection error**
```bash
# Test database connection
mysql -u imips_user -p imips

# Check MySQL status
sudo systemctl status mysql

# Verify credentials in .env file
```

**Issue: 502 Bad Gateway**
```bash
# Check if application is running
pm2 status

# Check Nginx logs
sudo tail -f /var/log/nginx/error.log

# Verify proxy_pass configuration
```

**Issue: CORS errors**
```bash
# Verify ALLOWED_ORIGINS in .env
# Must match exactly with frontend domain
# No trailing slashes
```

## 🎯 Performance Optimization

### 1. Enable Nginx Caching
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m max_size=100m;

location /api/inventory {
    proxy_cache api_cache;
    proxy_cache_valid 200 5m;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
}
```

### 2. Database Optimization
```sql
-- Add indexes for common queries
CREATE INDEX idx_created_at ON orders(created_at);
CREATE INDEX idx_user_activity ON users(last_activity);

-- Optimize tables
OPTIMIZE TABLE users, orders, inventory_items;
```

### 3. PM2 Cluster Mode
```bash
# Use all CPU cores
pm2 start app.js -i max --name imips-backend
```

## 🔐 Additional Security Recommendations

### 1. Implement IP Whitelisting (Optional)
```nginx
# In Nginx config
location /api/backup {
    allow 192.168.1.0/24;  # Your office network
    deny all;
    proxy_pass http://localhost:5000;
}
```

### 2. Set Up Intrusion Detection
```bash
# Install AIDE
sudo apt install aide
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily checks
echo "0 5 * * * /usr/bin/aide --check" | sudo crontab -
```

### 3. Enable Two-Factor Authentication
Extend the auth system to support 2FA:
- Add `speakeasy` npm package
- Store 2FA secrets securely
- Implement TOTP verification

### 4. Implement API Key Authentication
For external integrations:
- Create API keys table
- Generate secure API keys
- Implement API key middleware

## 📋 Compliance Checklist

### GDPR Compliance (if applicable)
- [ ] Data encryption at rest and in transit
- [ ] User data export functionality
- [ ] Right to be forgotten (soft delete)
- [ ] Privacy policy implemented
- [ ] Consent management
- [ ] Data breach notification procedure

### PCI DSS (if handling payments)
- [ ] No storage of full credit card numbers
- [ ] Use payment gateway (Stripe, PayPal)
- [ ] Encrypted transmission
- [ ] Regular security audits

### SOC 2 Considerations
- [ ] Access control logs
- [ ] Encryption key management
- [ ] Backup and recovery procedures
- [ ] Change management process
- [ ] Security incident response plan

## 🎓 Training Requirements

### For Administrators
1. Password management best practices
2. User role assignment procedures
3. Backup and restore procedures
4. Security incident response
5. Log monitoring and analysis

### For Developers
1. Secure coding practices
2. API security guidelines
3. Database security
4. Dependency management
5. Code review process

## ✅ Final Pre-Launch Checklist

**Critical (Must be complete)**
- [ ] All security keys generated and set
- [ ] Default admin password changed
- [ ] SSL certificate installed and valid
- [ ] Database backups configured
- [ ] All placeholder values replaced
- [ ] Production environment variables set
- [ ] File permissions properly configured
- [ ] Firewall rules configured
- [ ] Monitoring and alerting active
- [ ] Error tracking configured

**Important (Strongly recommended)**
- [ ] Rate limiting tested
- [ ] CORS configuration verified
- [ ] Email delivery tested
- [ ] All API endpoints tested
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Team trained on procedures
- [ ] Documentation reviewed and updated

**Nice to Have**
- [ ] CDN configured for static assets
- [ ] Database replication set up
- [ ] Automated deployment pipeline
- [ ] Performance monitoring
- [ ] User analytics

---

## 📚 Additional Resources

- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MySQL Security Guide](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [PM2 Documentation](https://pm2.keymetrics.io/docs/usage/quick-start/)
- [Nginx Security Tips](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)

---

**Last Updated:** 2025-01-04
**Version:** 1.0.0