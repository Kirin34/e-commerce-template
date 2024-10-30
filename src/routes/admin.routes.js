// project-root/src/routes/admin.routes.js
const router = require('express').Router();
const { body, query, param } = require('express-validator');
const mongoose = require('mongoose');
const { User, ShippingAddress } = require('../models');
const { authenticateToken, adminOnly } = require('../middleware/auth');

// Validation rules
const validateUserUpdate = [
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[A-Za-z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores and hyphens'),
  
  body('email')
    .optional()
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail()
    .toLowerCase(),
  
  body('role')
    .optional()
    .isIn(['customer', 'admin'])
    .withMessage('Invalid role specified'),
  
  body('status')
    .optional()
    .isIn(['active', 'suspended', 'deactivated'])
    .withMessage('Invalid status specified')
];

const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
];

// Helper functions
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

const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

/**
 * @route   GET /api/admin/dashboard
 * @desc    Get admin dashboard statistics
 * @access  Admin
 */
router.get('/dashboard', authenticateToken, adminOnly, async (req, res) => {
  try {
    const stats = {
      users: {
        total: await User.countDocuments(),
        active: await User.countDocuments({ status: 'active' }),
        new: await User.countDocuments({
          createdAt: { $gte: new Date(Date.now() - 24*60*60*1000) }
        })
      },
      addresses: {
        total: await ShippingAddress.countDocuments()
      },
      roles: {
        customers: await User.countDocuments({ role: 'customer' }),
        admins: await User.countDocuments({ role: 'admin' })
      }
    };

    // Get recent activities
    const recentActivities = await User.aggregate([
      { $unwind: '$loginHistory' },
      { $sort: { 'loginHistory.date': -1 } },
      { $limit: 10 },
      {
        $project: {
          username: 1,
          action: '$loginHistory.action',
          date: '$loginHistory.date',
          ipAddress: '$loginHistory.ipAddress'
        }
      }
    ]);

    res.json({
      stats,
      recentActivities
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Error fetching dashboard data' });
  }
});

/**
 * @route   GET /api/admin/users
 * @desc    Get all users with filtering and pagination
 * @access  Admin
 */
router.get('/users', 
  authenticateToken, 
  adminOnly,
  validatePagination,
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const search = req.query.search;
      const role = req.query.role;
      const status = req.query.status;

      // Build query
      const query = {};
      if (search) {
        query.$or = [
          { username: new RegExp(search, 'i') },
          { email: new RegExp(search, 'i') },
          { 'profile.firstName': new RegExp(search, 'i') },
          { 'profile.lastName': new RegExp(search, 'i') }
        ];
      }
      if (role) query.role = role;
      if (status) query.status = status;

      const users = await User.find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit);

      const total = await User.countDocuments(query);

      res.json({
        users,
        pagination: {
          current: page,
          pages: Math.ceil(total / limit),
          total,
          limit
        }
      });
    } catch (error) {
      console.error('Fetch users error:', error);
      res.status(500).json({ error: 'Error fetching users' });
    }
  }
);

/**
 * @route   GET /api/admin/users/:id
 * @desc    Get detailed user information
 * @access  Admin
 */
router.get('/users/:id',
  authenticateToken,
  adminOnly,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid user ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id)
        .select('-password');

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get user's addresses
      const addresses = await ShippingAddress.find({ user: user._id });

      // Get user's activity
      const activity = {
        loginHistory: user.loginHistory,
        addresses: addresses.length,
        lastActive: user.lastLogin
      };

      res.json({
        user,
        addresses,
        activity
      });
    } catch (error) {
      console.error('Fetch user error:', error);
      res.status(500).json({ error: 'Error fetching user details' });
    }
  }
);

/**
 * @route   PUT /api/admin/users/:id
 * @desc    Update user information
 * @access  Admin
 */
router.put('/users/:id',
  authenticateToken,
  adminOnly,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid user ID'),
    ...validateUserUpdate
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Prevent removing the last admin
      if (user.role === 'admin' && req.body.role === 'customer') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount === 1) {
          return res.status(400).json({ 
            error: 'Cannot remove the last admin user' 
          });
        }
      }

      // Update user fields
      const updatableFields = ['username', 'email', 'role', 'status', 'profile'];
      for (const field of updatableFields) {
        if (req.body[field]) {
          user[field] = req.body[field];
        }
      }

      await user.save();

      res.json({
        message: 'User updated successfully',
        user: user.toObject({ exclude: 'password' })
      });
    } catch (error) {
      console.error('Update user error:', error);
      res.status(500).json({ error: 'Error updating user' });
    }
  }
);

/**
 * @route   DELETE /api/admin/users/:id
 * @desc    Delete user
 * @access  Admin
 */
router.delete('/users/:id',
  authenticateToken,
  adminOnly,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid user ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Prevent deleting the last admin
      if (user.role === 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount === 1) {
          return res.status(400).json({ 
            error: 'Cannot delete the last admin user' 
          });
        }
      }

      // Delete user's addresses
      await ShippingAddress.deleteMany({ user: user._id });

      // Delete user
      await user.remove();

      res.json({
        message: 'User and associated data deleted successfully'
      });
    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({ error: 'Error deleting user' });
    }
  }
);

/**
 * @route   POST /api/admin/users/:id/suspend
 * @desc    Suspend user account
 * @access  Admin
 */
router.post('/users/:id/suspend',
  authenticateToken,
  adminOnly,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid user ID'),
    body('reason')
      .notEmpty()
      .withMessage('Suspension reason is required')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Prevent suspending the last admin
      if (user.role === 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount === 1) {
          return res.status(400).json({ 
            error: 'Cannot suspend the last admin user' 
          });
        }
      }

      user.status = 'suspended';
      user.suspensionDetails = {
        reason: req.body.reason,
        date: new Date(),
        suspendedBy: req.user.userId
      };

      await user.save();

      res.json({
        message: 'User suspended successfully',
        user: user.toObject({ exclude: 'password' })
      });
    } catch (error) {
      console.error('Suspend user error:', error);
      res.status(500).json({ error: 'Error suspending user' });
    }
  }
);

/**
 * @route   POST /api/admin/users/:id/reactivate
 * @desc    Reactivate suspended user account
 * @access  Admin
 */
router.post('/users/:id/reactivate',
  authenticateToken,
  adminOnly,
  [
    param('id')
      .custom(isValidObjectId)
      .withMessage('Invalid user ID')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      user.status = 'active';
      user.suspensionDetails = undefined;

      await user.save();

      res.json({
        message: 'User reactivated successfully',
        user: user.toObject({ exclude: 'password' })
      });
    } catch (error) {
      console.error('Reactivate user error:', error);
      res.status(500).json({ error: 'Error reactivating user' });
    }
  }
);

/**
 * @route   GET /api/admin/audit-log
 * @desc    Get system audit log
 * @access  Admin
 */
router.get('/audit-log',
  authenticateToken,
  adminOnly,
  validatePagination,
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 50;
      const startDate = req.query.startDate ? new Date(req.query.startDate) : null;
      const endDate = req.query.endDate ? new Date(req.query.endDate) : null;

      // Build date range query
      const dateQuery = {};
      if (startDate || endDate) {
        dateQuery.date = {};
        if (startDate) dateQuery.date.$gte = startDate;
        if (endDate) dateQuery.date.$lte = endDate;
      }

      const activities = await User.aggregate([
        { $unwind: '$loginHistory' },
        { $match: dateQuery },
        { $sort: { 'loginHistory.date': -1 } },
        { $skip: (page - 1) * limit },
        { $limit: limit },
        {
          $project: {
            username: 1,
            email: 1,
            action: '$loginHistory.action',
            date: '$loginHistory.date',
            ipAddress: '$loginHistory.ipAddress'
          }
        }
      ]);

      const total = await User.aggregate([
        { $unwind: '$loginHistory' },
        { $match: dateQuery },
        { $count: 'total' }
      ]);

      res.json({
        activities,
        pagination: {
          current: page,
          pages: Math.ceil((total[0]?.total || 0) / limit),
          total: total[0]?.total || 0,
          limit
        }
      });
    } catch (error) {
      console.error('Audit log error:', error);
      res.status(500).json({ error: 'Error fetching audit log' });
    }
  }
);

module.exports = router;