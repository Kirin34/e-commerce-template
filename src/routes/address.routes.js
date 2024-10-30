// src/routes/address.routes.js
const router = require('express').Router();
const { body, param, query, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const { ShippingAddress } = require('../models');
const { authenticateToken } = require('../middleware/auth');

// Validation rules
const addressValidation = [
  body('addressName')
    .trim()
    .notEmpty()
    .withMessage('Address name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Address name must be between 2 and 50 characters'),

  body('recipient.firstName')
    .trim()
    .notEmpty()
    .withMessage('Recipient first name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),

  body('recipient.lastName')
    .trim()
    .notEmpty()
    .withMessage('Recipient last name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),

  body('recipient.phoneNumber')
    .trim()
    .notEmpty()
    .withMessage('Phone number is required')
    .matches(/^\+?[\d\s-]+$/)
    .withMessage('Invalid phone number format'),

  body('address.street')
    .trim()
    .notEmpty()
    .withMessage('Street address is required')
    .isLength({ min: 5, max: 100 })
    .withMessage('Street address must be between 5 and 100 characters'),

  body('address.city')
    .trim()
    .notEmpty()
    .withMessage('City is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('City must be between 2 and 50 characters'),

  body('address.state')
    .trim()
    .notEmpty()
    .withMessage('State is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('State must be between 2 and 50 characters'),

  body('address.zipCode')
    .trim()
    .notEmpty()
    .withMessage('ZIP code is required')
    .matches(/^[0-9]{5}(?:-[0-9]{4})?$/)
    .withMessage('Invalid ZIP code format'),

  body('address.country')
    .trim()
    .notEmpty()
    .withMessage('Country is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Country must be between 2 and 50 characters')
    .default('Italy'),

  body('isDefault')
    .optional()
    .isBoolean()
    .withMessage('isDefault must be a boolean value'),

  body('notes')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
];

// Helper function to validate ObjectId
const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

/**
 * @route   POST /api/addresses
 * @desc    Create a new shipping address
 * @access  Private
 */
router.post('/', 
  authenticateToken,
  addressValidation,
  handleValidationErrors,
  async (req, res) => {
    try {
      const addressData = {
        ...req.body,
        user: req.user.userId
      };

      // If this is the first address or marked as default
      if (addressData.isDefault) {
        await ShippingAddress.updateMany(
          { user: req.user.userId },
          { $set: { isDefault: false } }
        );
      }

      // If this is the user's first address, make it default
      const addressCount = await ShippingAddress.countDocuments({ user: req.user.userId });
      if (addressCount === 0) {
        addressData.isDefault = true;
      }

      const address = new ShippingAddress(addressData);
      await address.save();

      res.status(201).json({
        message: 'Shipping address created successfully',
        address
      });
    } catch (error) {
      console.error('Create address error:', error);
      res.status(500).json({ error: 'Error creating shipping address' });
    }
  }
);

/**
 * @route   GET /api/addresses
 * @desc    Get all shipping addresses for user
 * @access  Private
 */
router.get('/',
  authenticateToken,
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 50 })
      .withMessage('Limit must be between 1 and 50')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;

      const addresses = await ShippingAddress.find({ user: req.user.userId })
        .sort({ isDefault: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit);

      const total = await ShippingAddress.countDocuments({ user: req.user.userId });

      res.json({
        addresses,
        pagination: {
          current: page,
          pages: Math.ceil(total / limit),
          total,
          limit
        }
      });
    } catch (error) {
      console.error('Fetch addresses error:', error);
      res.status(500).json({ error: 'Error fetching shipping addresses' });
    }
  }
);

/**
 * @route   GET /api/addresses/:id
 * @desc    Get a specific shipping address
 * @access  Private
 */
router.get('/:id',
  authenticateToken,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid address ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const address = await ShippingAddress.findOne({
        _id: req.params.id,
        user: req.user.userId
      });

      if (!address) {
        return res.status(404).json({ error: 'Shipping address not found' });
      }

      res.json(address);
    } catch (error) {
      console.error('Fetch address error:', error);
      res.status(500).json({ error: 'Error fetching shipping address' });
    }
  }
);

/**
 * @route   PUT /api/addresses/:id
 * @desc    Update a shipping address
 * @access  Private
 */
router.put('/:id',
  authenticateToken,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid address ID'),
    ...addressValidation
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const address = await ShippingAddress.findOne({
        _id: req.params.id,
        user: req.user.userId
      });

      if (!address) {
        return res.status(404).json({ error: 'Shipping address not found' });
      }

      // Handle default address changes
      if (req.body.isDefault && !address.isDefault) {
        await ShippingAddress.updateMany(
          { user: req.user.userId },
          { $set: { isDefault: false } }
        );
      }

      // Update address fields
      Object.assign(address, req.body);
      await address.save();

      res.json({
        message: 'Shipping address updated successfully',
        address
      });
    } catch (error) {
      console.error('Update address error:', error);
      res.status(500).json({ error: 'Error updating shipping address' });
    }
  }
);

/**
 * @route   DELETE /api/addresses/:id
 * @desc    Delete a shipping address
 * @access  Private
 */
router.delete('/:id',
  authenticateToken,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid address ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const address = await ShippingAddress.findOne({
        _id: req.params.id,
        user: req.user.userId
      });

      if (!address) {
        return res.status(404).json({ error: 'Shipping address not found' });
      }

      const wasDefault = address.isDefault;
      await address.deleteOne(); // Updated from remove() to deleteOne()

      // If the deleted address was default, make the most recent address default
      if (wasDefault) {
        const newDefaultAddress = await ShippingAddress.findOne({ user: req.user.userId })
          .sort({ createdAt: -1 });
        
        if (newDefaultAddress) {
          newDefaultAddress.isDefault = true;
          await newDefaultAddress.save();
        }
      }

      res.json({
        message: 'Shipping address deleted successfully',
        deletedAddress: address
      });
    } catch (error) {
      console.error('Delete address error:', error);
      res.status(500).json({ error: 'Error deleting shipping address' });
    }
  }
);

/**
 * @route   PUT /api/addresses/:id/set-default
 * @desc    Set an address as default
 * @access  Private
 */
router.put('/:id/set-default',
  authenticateToken,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid address ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const address = await ShippingAddress.findOne({
        _id: req.params.id,
        user: req.user.userId
      });

      if (!address) {
        return res.status(404).json({ error: 'Shipping address not found' });
      }

      // Remove default status from all other addresses
      await ShippingAddress.updateMany(
        { user: req.user.userId, _id: { $ne: address._id } },
        { $set: { isDefault: false } }
      );

      // Set this address as default
      address.isDefault = true;
      await address.save();

      res.json({
        message: 'Address set as default successfully',
        address
      });
    } catch (error) {
      console.error('Set default address error:', error);
      res.status(500).json({ error: 'Error setting default address' });
    }
  }
);

module.exports = router;