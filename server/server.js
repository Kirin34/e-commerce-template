// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const BlacklistedTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 86400 // Automatically delete documents after 24 hours
  }
});

const ShippingAddressSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  addressName: {
    type: String,
    required: true,
    trim: true
  },
  recipient: {
    firstName: {
      type: String,
      required: true,
      trim: true
    },
    lastName: {
      type: String,
      required: true,
      trim: true
    },
    phoneNumber: {
      type: String,
      required: true,
      trim: true
    }
  },
  address: {
    street: {
      type: String,
      required: true,
      trim: true
    },
    city: {
      type: String,
      required: true,
      trim: true
    },
    state: {
      type: String,
      required: true,
      trim: true
    },
    zipCode: {
      type: String,
      required: true,
      trim: true
    },
    country: {
      type: String,
      required: true,
      trim: true,
      default: 'Italy'
    }
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  notes: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  profile: {
    firstName: String,
    lastName: String,
    phoneNumber: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  loginHistory: [{
    date: Date,
    action: String, // 'login' or 'logout'
    ipAddress: String
  }]
});

const SessionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 86400 // 24 hours
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  ipAddress: String,
  userAgent: String
});

const BlacklistedToken = mongoose.model('BlacklistedToken', BlacklistedTokenSchema);
const User = mongoose.model('User', UserSchema);
const ShippingAddress = mongoose.model('ShippingAddress', ShippingAddressSchema);
const Session = mongoose.model('Session', SessionSchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Check if token is blacklisted
    const blacklistedToken = await BlacklistedToken.findOne({ token });
    if (blacklistedToken) {
      return res.status(401).json({ error: 'Token has been invalidated' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
      }

      // Update session last activity
      await Session.findOneAndUpdate(
        { token },
        { lastActivity: new Date() }
      );

      req.user = user;
      req.token = token;
      next();
    });
  } catch (error) {
    res.status(500).json({ error: 'Error authenticating token' });
  }
};

// Role Check Middleware
const checkRole = (roles) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user.userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!roles.includes(user.role)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      next();
    } catch (error) {
      res.status(500).json({ error: 'Error checking permissions' });
    }
  };
};

const adminOnly = checkRole(['admin']);

// Validation Middleware
const validateUser = [
  body('username').isLength({ min: 3 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 })
];

const validateShippingAddress = [
  body('addressName').notEmpty().trim(),
  body('recipient.firstName').notEmpty().trim(),
  body('recipient.lastName').notEmpty().trim(),
  body('recipient.phoneNumber').notEmpty().trim(),
  body('address.street').notEmpty().trim(),
  body('address.city').notEmpty().trim(),
  body('address.state').notEmpty().trim(),
  body('address.zipCode').notEmpty().trim()
];

// Auth Routes
app.post('/register', validateUser, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, profile } = req.body;

    const userExists = await User.findOne({ $or: [{ username }, { email }] });
    if (userExists) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      profile
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create session
    const session = new Session({
      user: user._id,
      token,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    await session.save();

    // Update user login history
    user.lastLogin = new Date();
    user.loginHistory.push({
      date: new Date(),
      action: 'login',
      ipAddress: req.ip
    });
    await user.save();

    res.json({ token, role: user.role });
  } catch (error) {
    res.status(500).json({ error: 'Error during login' });
  }
});

app.post('/logout', authenticateToken, async (req, res) => {
  try {
    // Add token to blacklist
    const blacklistedToken = new BlacklistedToken({
      token: req.token
    });
    await blacklistedToken.save();

    // Remove session
    await Session.findOneAndDelete({ token: req.token });

    // Update user login history
    const user = await User.findById(req.user.userId);
    user.loginHistory.push({
      date: new Date(),
      action: 'logout',
      ipAddress: req.ip
    });
    await user.save();

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error during logout' });
  }
});

app.post('/logout/all', authenticateToken, async (req, res) => {
  try {
    // Get all active sessions for user
    const sessions = await Session.find({ user: req.user.userId });
    
    // Blacklist all tokens
    await BlacklistedToken.insertMany(
      sessions.map(session => ({ token: session.token }))
    );

    // Remove all sessions
    await Session.deleteMany({ user: req.user.userId });

    res.json({ message: 'Logged out from all devices successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error during logout from all devices' });
  }
});

// Profile Routes
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password')
      .select('-loginHistory');
      
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching profile' });
  }
});

app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phoneNumber } = req.body;
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.profile = {
      firstName: firstName || user.profile.firstName,
      lastName: lastName || user.profile.lastName,
      phoneNumber: phoneNumber || user.profile.phoneNumber
    };

    await user.save();
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error updating profile' });
  }
});

// Shipping Address Routes
app.post('/shipping-addresses', authenticateToken, validateShippingAddress, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const shippingData = {
      ...req.body,
      user: req.user.userId
    };

    if (shippingData.isDefault) {
      await ShippingAddress.updateMany(
        { user: req.user.userId },
        { $set: { isDefault: false } }
      );
    }

    const address = new ShippingAddress(shippingData);
    await address.save();

    res.status(201).json(address);
  } catch (error) {
    res.status(500).json({ error: 'Error creating shipping address' });
  }
});

app.get('/shipping-addresses', authenticateToken, async (req, res) => {
  try {
    const addresses = await ShippingAddress.find({ user: req.user.userId })
      .sort({ isDefault: -1, createdAt: -1 });
    res.json(addresses);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching shipping addresses' });
  }
});

app.put('/shipping-addresses/:id', authenticateToken, validateShippingAddress, async (req, res) => {
  try {
    const address = await ShippingAddress.findOne({
      _id: req.params.id,
      user: req.user.userId
    });

    if (!address) {
      return res.status(404).json({ error: 'Shipping address not found' });
    }

    if (req.body.isDefault && !address.isDefault) {
      await ShippingAddress.updateMany(
        { user: req.user.userId },
        { $set: { isDefault: false } }
      );
    }

    Object.assign(address, req.body);
    address.updatedAt = new Date();
    await address.save();

    res.json(address);
  } catch (error) {
    res.status(500).json({ error: 'Error updating shipping address' });
  }
});

app.delete('/shipping-addresses/:id', authenticateToken, async (req, res) => {
  try {
    const address = await ShippingAddress.findOne({
      _id: req.params.id,
      user: req.user.userId
    });

    if (!address) {
      return res.status(404).json({ error: 'Shipping address not found' });
    }

    await address.remove();

    if (address.isDefault) {
      const newDefaultAddress = await ShippingAddress.findOne({ user: req.user.userId })
        .sort({ createdAt: -1 });
      
      if (newDefaultAddress) {
        newDefaultAddress.isDefault = true;
        await newDefaultAddress.save();
      }
    }

    res.json({ message: 'Shipping address deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting shipping address' });
  }
});

// Admin Routes
app.get('/admin/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .select('-loginHistory');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users' });
  }
});

// Continuing from previous code...

// Session Management (continued)
app.get('/session/validate', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      valid: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profile: user.profile
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error validating session' });
  }
});

app.get('/session/active', authenticateToken, async (req, res) => {
  try {
    const sessions = await Session.find({ user: req.user.userId })
      .sort({ lastActivity: -1 });

    res.json(sessions.map(session => ({
      id: session._id,
      createdAt: session.createdAt,
      lastActivity: session.lastActivity,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      current: session.token === req.token
    })));
  } catch (error) {
    res.status(500).json({ error: 'Error fetching active sessions' });
  }
});

app.delete('/session/:sessionId', authenticateToken, async (req, res) => {
  try {
    const session = await Session.findOne({
      _id: req.params.sessionId,
      user: req.user.userId
    });

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Add token to blacklist
    const blacklistedToken = new BlacklistedToken({
      token: session.token
    });
    await blacklistedToken.save();

    // Remove session
    await session.remove();

    res.json({ message: 'Session terminated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error terminating session' });
  }
});

// User Settings and Preferences
app.put('/settings/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error updating password' });
  }
});

// Account History
app.get('/account/history', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('loginHistory');
    
    res.json(user.loginHistory.sort((a, b) => b.date - a.date));
  } catch (error) {
    res.status(500).json({ error: 'Error fetching account history' });
  }
});

// Admin Additional Routes
app.get('/admin/users/:userId/sessions', authenticateToken, adminOnly, async (req, res) => {
  try {
    const sessions = await Session.find({ user: req.params.userId })
      .sort({ lastActivity: -1 });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user sessions' });
  }
});

app.put('/admin/users/:userId/role', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;
    
    if (!['customer', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { role },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error updating user role' });
  }
});

// Cleanup functions
const cleanupBlacklistedTokens = async () => {
  try {
    const expiryDate = new Date(Date.now() - 86400000); // 24 hours ago
    await BlacklistedToken.deleteMany({ createdAt: { $lt: expiryDate } });
  } catch (error) {
    console.error('Error cleaning up blacklisted tokens:', error);
  }
};

const cleanupExpiredSessions = async () => {
  try {
    const expiryDate = new Date(Date.now() - 86400000); // 24 hours ago
    await Session.deleteMany({ lastActivity: { $lt: expiryDate } });
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
};

// Schedule cleanup tasks
setInterval(cleanupBlacklistedTokens, 43200000); // Every 12 hours
setInterval(cleanupExpiredSessions, 43200000); // Every 12 hours

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Initial cleanup
  cleanupBlacklistedTokens();
  cleanupExpiredSessions();
});

module.exports = app;