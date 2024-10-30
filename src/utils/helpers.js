const generateToken = (user) => {
    return jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
  };
  
  const handleError = (res, error, message = 'Internal server error') => {
    console.error(error);
    res.status(500).json({ error: message });
  };
  
  module.exports = {
    generateToken,
    handleError
  };