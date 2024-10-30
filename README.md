# E-commerce Backend API

A Node.js/Express backend API for an e-commerce platform.

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT (JSON Web Tokens)
- **Validation**: Express Validator
- **Development**: Nodemon
- **Testing**: Jest
- **Documentation**: Postman Collection

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (or Docker for containerized MongoDB)
- npm or yarn package manager

## Installation

1. Clone the repository
```bash
git clone <repository-url>
cd e-commerce-template
```

2. Install dependencies
```bash
npm install
```

3. Create a `.env` file in the root directory
```env
PORT=3000
MONGODB_URI=mongodb://localhost:27017/your_database_name
JWT_SECRET=your_jwt_secret_here
```

4. Start MongoDB using Docker (optional)
```bash
# Start MongoDB container
npm run db

# Stop MongoDB container
npm run db:stop

# Remove MongoDB container
npm run db:remove
```

5. Start the development server
```bash
npm run dev
```

## Project Structure
```
.
├── README.md
├── client                  # React frontend application
├── package.json
├── server.js              # Application entry point
└── src
    ├── config             # Configuration files
    ├── middleware         # Custom middleware
    ├── models             # Database models
    ├── routes            # API routes
    └── utils             # Utility functions
```

## Available Scripts

```bash
# Start development server
npm run dev

# Start production server
npm start

# Start MongoDB with Docker
npm run db

# Stop MongoDB Docker container
npm run db:stop

# Remove MongoDB Docker container
npm run db:remove

# Run tests
npm test

# Run linting
npm run lint
```

## API Documentation

Complete API documentation is available in the Postman collection located in the `postman` directory. Import the collection into Postman to explore all available endpoints and their specifications.