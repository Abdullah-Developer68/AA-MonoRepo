const userModel = require("../models/user.model.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const sendOTP = require("../utils/sendOTP.js");
const dbConnect = require("../config/dbConnect.js");

dotenv.config();

const secretKey = process.env.JWT_KEY;

// Utility function to extract token from Authorization header or cookies
const extractToken = (req) => {
  // First, try to get token from Authorization header (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  // Fallback to cookie-based token
  return req.cookies.token;
};

// Centralized cookie configuration for same-domain deployment
const getCookieOptions = (req) => {
  const isProduction = process.env.NODE_ENV === "production";

  const options = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax", // Same-domain so lax is sufficient
    path: "/",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  };

  if (isProduction) {
    const configuredDomain = process.env.COOKIE_DOMAIN;
    const requestHost =
      req?.hostname ||
      req?.headers?.host?.split(":")[0] ||
      (typeof req.get === "function" && req.get("host")?.split(":")[0]);

    if (configuredDomain) {
      options.domain = configuredDomain;
    } else if (requestHost) {
      options.domain = requestHost;
    }
  }

  return options;
};

const makNSenOTP = async (req, res) => {
  dbConnect();
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 mins expiry

  let user = await userModel.findOne({ email });
  if (!user) {
    // Create new user with verifying role and required fields
    user = await userModel.create({
      email,
      otp,
      otpExpiry,
      role: "verifying",
      username: "temp",
      password: "N/A",
    });
  } else {
    // If user exists
    res.status(409).json({
      message: "Your account already exists, so you should just login!",
    });
    return;
  }
  await sendOTP(email, otp);
  res.status(200).json({ message: "OTP sent" });
};

const verifyOTP = async (req, res) => {
  dbConnect();
  const { email, otp } = req.body;
  const user = await userModel.findOne({ email, role: "verifying" });
  if (!user || user.otp !== otp || user.otpExpiry < new Date()) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }
  // OTP verified - do NOT clear otp/otpExpiry yet
  res.status(200).json({ message: "OTP verified" });
};

const signUp = async (req, res) => {
  dbConnect();
  try {
    const { email, password, username } = req.body;
    // Find user with role verifying
    const user = await userModel.findOne({ email, role: "verifying" });
    if (!user) {
      return res.status(400).json({
        success: false,
        message:
          "No pending verification for this email. Please start signup again.",
      });
    }
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Update user fields and set role to user
    user.username = username;
    user.password = hashedPassword;
    user.role = "user";
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();
    // Create token and sign in
    const token = jwt.sign(
      {
        userid: user._id,
        email: user.email,
        username: user.username,
        profilePic: user.profilePic,
        role: user.role,
      },
      secretKey,
      { expiresIn: "24h" } // Add token expiration
    );

    // Set cookie as fallback (for compatibility)
    res.cookie("token", token, getCookieOptions(req));

    // Send token in response body for localStorage storage
    res.status(201).json({
      success: true,
      token, // Include token in response for localStorage
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePic: user.profilePic,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Registration Error:", error.message);
    res.status(500).json({
      status: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

const login = async (req, res) => {
  dbConnect();
  try {
    const { email, password } = req.body;

    // Check if credentials are provided
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Email and password are required for login!",
      });
    }

    // Check if user exists
    const userExist = await userModel.findOne({ email });

    if (!userExist) {
      return res
        .status(401)
        .json({ success: false, status: false, message: "User not found!" });
    }

    // Check if user was registered through Google (no password but has googleId)
    if (
      (!userExist.password || userExist.password === "N/A") &&
      userExist.googleId
    ) {
      return res.status(400).json({
        success: false,
        status: false,
        message:
          "You are registered through Google. Please use Google login to sign in.",
      });
    }

    const passwordMatch = await bcrypt.compare(password, userExist.password);
    if (!passwordMatch) {
      return res.status(401).json({
        status: false,
        message: "Either email or password is incorrect!",
      });
    }

    // Create token and send as cookie
    const token = jwt.sign(
      {
        userid: userExist._id,
        email: userExist.email,
        username: userExist.username,
        profilePic: userExist.profilePic,
        role: userExist.role,
      },
      secretKey,
      { expiresIn: "24h" } // Add token expiration
    );

    // Set cookie as fallback (for compatibility)
    res.cookie("token", token, getCookieOptions(req));

    const user = {
      id: userExist._id,
      username: userExist.username,
      email: userExist.email,
      role: userExist.role,
      profilePic: userExist.profilePic,
    };

    // Send login success response with token for localStorage
    res.status(200).json({
      success: true,
      token, // Include token in response for localStorage
      user,
      message: "You have been logged in!",
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ message: "Unauthorized!" });
  }
};

const logout = (req, res) => {
  dbConnect();
  try {
    const baseCookieOptions = getCookieOptions(req);
    const clearCookieOptions = {
      ...baseCookieOptions,
      expires: new Date(0),
      maxAge: 0,
    };

    // Clear using the same options used during login
    res.clearCookie("token", clearCookieOptions);
    res.cookie("token", "", clearCookieOptions);

    // Also attempt host-only clearing to cover any domain mismatches
    if (clearCookieOptions.domain) {
      const hostOnlyOptions = { ...clearCookieOptions };
      delete hostOnlyOptions.domain;
      res.clearCookie("token", hostOnlyOptions);
      res.cookie("token", "", hostOnlyOptions);
    }

    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout Error:", error.message);
    res.status(500).json({
      success: false,
      message: "Logout failed",
    });
  }
};

//  helps to stay logged in even after refreshing the page
const verifyToken = async (req, res) => {
  console.log("Verifying token...");
  dbConnect();
  try {
    // Use utility function to extract token from Authorization header or cookies
    const token = extractToken(req);
    console.log("token was not deleted");
    console.log(token);
    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "No authentication token found" });
    }

    const decoded = jwt.verify(token, secretKey);

    res.json({
      success: true,
      user: {
        id: decoded.userid,
        username: decoded.username,
        email: decoded.email,
        profilePic: decoded.profilePic,
        role: decoded.role,
      },
    });
  } catch (error) {
    console.error("Token verification error:", error);

    // Handle specific JWT errors
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Authentication token expired.",
      });
    }

    res
      .status(401)
      .json({ success: false, message: "Token verification failed" });
  }
};

module.exports = { makNSenOTP, verifyOTP, signUp, login, logout, verifyToken };
