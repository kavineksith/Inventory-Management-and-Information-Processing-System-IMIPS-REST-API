const emailService = require("./emailService");

// Add this to routes/users.js after password change
async function notifyPasswordChanged(userId, userEmail, userName) {
    try {
        await emailService.sendPasswordChangedNotification(userEmail, userName);
        console.log('Password change notification sent to:', userEmail);
    } catch (error) {
        console.error('Failed to send password change notification:', error);
    }
}

module.exports = {
    notifyPasswordChanged
}