// Import mongoose ODM (Object Data Modeling) library
const mongoose = require('mongoose');

// Create an async function to handle database connection
const connectDB = async () => {
  try {
    // Attempt to connect to MongoDB using the connection string from environment variables
    await mongoose.connect(process.env.MONGODB_URI, {
      // Connection options
      useNewUrlParser: true,     // Use new URL parser
      useUnifiedTopology: true   // Use new Server Discovery and Monitoring engine
    });
    
    // If connection is successful, log it
    console.log('Connected to MongoDB');
  } catch (error) {
    // If connection fails, log the error and exit the process
    console.error('MongoDB connection error:', error);
    process.exit(1);  // Exit with failure code
  }
};

// Export the connection function
module.exports = connectDB;
