# E-commerce Backend Project

This project is a Node.js backend for an e-commerce application, using Express and MongoDB.

## Prerequisites

- Node.js (v12 or later)
- npm (usually comes with Node.js)
- Docker (for running MongoDB in a container)

## Setup

1. Clone the repository:
   ```
   git clone <your-repo-url>
   cd <your-project-directory>
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory with the following content:
   ```
   MONGODB_URI=mongodb://localhost:27017/myshop
   PORT=3000
   ```

## Running the Database

We use MongoDB running in a Docker container. To start the database:

```
npm run db
```

This command will start a MongoDB container named "mongodb" if it doesn't exist, or start it if it already exists.

## Running the Server

To start the server:

```
npm start
```

The server will start on the port specified in your .env file (default is 3000).

## API Endpoints

- POST /users - Create a new user
- GET /users - Get all users
- GET /users/:id - Get a specific user by ID

## Development

For development, you can use:

```
npm run dev
```

This will start the server with nodemon, which will automatically restart the server when you make changes to the code.

## Testing the API

You can use tools like Postman or curl to test the API endpoints. For example:

```
curl http://localhost:3000/users
```

## Stopping the Database

To stop the MongoDB container:

```
npm run db:stop
```

## Notes

- Remember to secure your application before deploying to production.
- Consider implementing user authentication and authorization.
- Always use HTTPS in a production environment.