const { body, param, query, validationResult } = require('express-validator');
const { executeQuery } = require('../config/database');

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            message: 'Validation failed',
            errors: errors.array()
        });
    }
    next();
};

// Auth validations
const validateLogin = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email is required'),
    body('password')
        .isLength({ min: 1 })
        .withMessage('Password is required'),
    handleValidationErrors
];

const validateRegister = [
    body('name')
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Name must be between 2 and 255 characters'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email is required')
        .custom(async (email) => {
            const existingUser = await executeQuery(
                'SELECT id FROM users WHERE email = ? AND is_deleted = false',
                [email]
            );
            if (existingUser.length > 0) {
                throw new Error('Email already registered');
            }
        }),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain uppercase, lowercase, number and special character'),
    body('role')
        .isIn(['Admin', 'Manager', 'Staff'])
        .withMessage('Invalid role'),
    handleValidationErrors
];

// User validations
const validateUserUpdate = [
    param('id')
        .isLength({ min: 1 })
        .withMessage('User ID is required'),
    body('name')
        .optional()
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Name must be between 2 and 255 characters'),
    body('email')
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email is required'),
    body('role')
        .optional()
        .isIn(['Admin', 'Manager', 'Staff'])
        .withMessage('Invalid role'),
    handleValidationErrors
];

const validatePasswordChange = [
    body('currentPassword')
        .isLength({ min: 1 })
        .withMessage('Current password is required'),
    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('New password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain uppercase, lowercase, number and special character'),
    handleValidationErrors
];

// Inventory validations
const validateInventoryItem = [
    body('name')
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Name must be between 2 and 255 characters'),
    body('sku')
        .trim()
        .isLength({ min: 3, max: 50 })
        .withMessage('SKU must be between 3 and 50 characters')
        .custom(async (sku, { req }) => {
            const existingItem = await executeQuery(
                'SELECT id FROM inventory_items WHERE sku = ? AND is_deleted = false AND id != ?',
                [sku, req.params.id || '']
            );
            if (existingItem.length > 0) {
                throw new Error('SKU already exists');
            }
        }),
    body('quantity')
        .isInt({ min: 0 })
        .withMessage('Quantity must be a non-negative integer'),
    body('threshold')
        .isInt({ min: 0 })
        .withMessage('Threshold must be a non-negative integer'),
    body('category')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Category must be between 2 and 100 characters'),
    body('price')
        .isFloat({ min: 0 })
        .withMessage('Price must be a positive number'),
    body('warranty_period_months')
        .optional()
        .isInt({ min: 0 })
        .withMessage('Warranty period must be a non-negative integer'),
    handleValidationErrors
];

// Order validations
const validateOrder = [
    body('customer_name')
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Customer name must be between 2 and 255 characters'),
    body('customer_contact')
        .trim()
        .isLength({ min: 5, max: 50 })
        .withMessage('Customer contact must be between 5 and 50 characters'),
    body('customer_address')
        .trim()
        .isLength({ min: 10 })
        .withMessage('Address must be at least 10 characters'),
    body('customer_email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid customer email is required'),
    body('items')
        .isArray({ min: 1 })
        .withMessage('Order must contain at least one item'),
    body('items.*.inventory_item_id')
        .isLength({ min: 1 })
        .withMessage('Item ID is required'),
    body('items.*.quantity')
        .isInt({ min: 1 })
        .withMessage('Item quantity must be at least 1'),
    handleValidationErrors
];

// Inquiry validations
const validateInquiry = [
    body('customer_name')
        .trim()
        .isLength({ min: 2, max: 255 })
        .withMessage('Customer name must be between 2 and 255 characters'),
    body('customer_email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid customer email is required'),
    body('inquiry_details')
        .trim()
        .isLength({ min: 10 })
        .withMessage('Inquiry details must be at least 10 characters'),
    handleValidationErrors
];

// Discount validations
const validateDiscount = [
    body('code')
        .trim()
        .isLength({ min: 3, max: 50 })
        .withMessage('Discount code must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9-_]+$/)
        .withMessage('Discount code can only contain letters, numbers, hyphens and underscores')
        .custom(async (code, { req }) => {
            const existingDiscount = await executeQuery(
                'SELECT id FROM discounts WHERE code = ? AND is_deleted = false AND id != ?',
                [code, req.params.id || '']
            );
            if (existingDiscount.length > 0) {
                throw new Error('Discount code already exists');
            }
        }),
    body('description')
        .trim()
        .isLength({ min: 10, max: 1000 })
        .withMessage('Description must be between 10 and 1000 characters'),
    body('type')
        .isIn(['Percentage', 'FixedAmount'])
        .withMessage('Invalid discount type'),
    body('value')
        .isFloat({ min: 0 })
        .withMessage('Discount value must be a positive number')
        .custom((value, { req }) => {
            if (req.body.type === 'Percentage' && value > 100) {
                throw new Error('Percentage discount cannot exceed 100%');
            }
            return true;
        }),
    body('min_spend')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Minimum spend must be a positive number'),
    body('min_items')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Minimum items must be at least 1'),
    handleValidationErrors
];

module.exports = {
    validateLogin,
    validateRegister,
    validateUserUpdate,
    validatePasswordChange,
    validateInventoryItem,
    validateOrder,
    validateInquiry,
    validateDiscount,
    handleValidationErrors
};