const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

// Define allowed origins - simplified for same-domain deployment
const allowedOrigins = [
  "http://localhost:5173", // Development client
  "http://localhost:3000", // Development server
  "https://localhost:3000",
].filter(Boolean);

// Simplified CORS middleware for same-domain deployment
const corsMiddleware = cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (same domain, mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    // In production with same domain, most requests won't have origin header
    if (process.env.NODE_ENV === "production") {
      return callback(null, true);
    }

    // In development, check allowed origins
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // In development, be more permissive
    return callback(null, true);
  },
  credentials: true, // Still needed for cookies
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin",
  ],
  exposedHeaders: ["Set-Cookie"], // Allow client to see Set-Cookie header
  optionsSuccessStatus: 200, // For legacy browser support
  preflightContinue: false,
});

module.exports = corsMiddleware;
