require("dotenv").config();

const express       = require("express");
const ejs           = require("ejs");
const bodyparser    = require("body-parser");
const mongoose      = require("mongoose");
const passport      = require("passport");
const bcrypt        = require("bcrypt");
const fs            = require("fs");
const session       = require("express-session");
const nodemailer    = require("nodemailer");
const multer        = require("multer");
const path          = require("path");
const csrf          = require("csrf");
const mongoSanitize = require("express-mongo-sanitize");
const validator     = require("validator");
const rateLimit     = require("express-rate-limit");
const flash         = require("connect-flash");
const crypto        = require("crypto");

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

const app = express();

app.set("views", __dirname + "/views");
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/Public"));

// 1️⃣ SESSION
app.use(session({
  secret:            process.env.SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === "production", // true in prod, false in dev
    sameSite:  "strict",
    maxAge:    1000 * 60 * 60 * 24
  }
}));

// 2️⃣ FLASH
app.use(flash());

// 3️⃣ FLASH LOCALS
app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error   = req.flash("error");
  next();
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "Public/uploads/lab");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files allowed"));
    }
  }
});

// 4️⃣ CSRF SECRET
const tokens = new csrf();

app.use((req, res, next) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  res.locals.csrfToken = tokens.create(req.session.csrfSecret);
  next();
});

// 5️⃣ CSRF VERIFIER
app.use((req, res, next) => {
  const skipRoutes = ["/login", "/logout"];
  if (
    req.method === "POST" &&
    !skipRoutes.includes(req.path) &&
    !req.is("multipart/form-data")
  ) {
    const token = req.body?._csrf;

    if (!req.session.csrfSecret) {
      req.flash("error", "Invalid request. Please try again.");
      return res.redirect("/login");
    }

    if (!token) {
      req.flash("error", "Invalid request. Please try again.");
      const referer = req.get("Referer");
      if (referer) return res.redirect(referer);
      return res.redirect("/dashboard");
    }

    if (!tokens.verify(req.session.csrfSecret, token)) {
      req.flash("error", "Invalid request. Please try again.");
      const referer = req.get("Referer");
      if (referer) return res.redirect(referer);
      return res.redirect("/dashboard");
    }
  }
  next();
});

// 6️⃣ RATE LIMITER
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      5,
  handler:  (req, res) => {
    req.flash("error", "Too many login attempts. Please try again in 15 minutes.");
    return res.redirect("/login");
  }
});

// 7️⃣ TRANSPORTER
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// 8️⃣ isLoggedIn MIDDLEWARE
function isLoggedIn(req, res, next) {
  if (!req.session || !req.session.userId) {
    req.flash("error", "Please login first");
    return res.redirect("/login");
  }
  next();
}

// ✅ allow() — role-based access middleware
function allow(...roles) {
  return (req, res, next) => {
    if (!req.session || !req.session.userId) {
      req.flash("error", "Please login first");
      return res.redirect("/login");
    }
    if (!roles.includes(req.session.role)) {
      req.flash("error", "You do not have permission to access that page");
      return res.redirect("/dashboard");
    }
    next();
  };
}

// 9️⃣ SANITIZE HELPER
function sanitizeInput(value) {
  if (!value) return "";
  return validator.escape(String(value).trim());
}

const User                  = require("./model/user");
const Patient               = require("./model/patient");
const Visit                 = require("./model/visit");
const Admission             = require("./model/admission");
const generatePatientSummary = require("./generatePatientSummary");

app.get("/login", (req, res) => {
  res.render("Login", {
    success: res.locals.success[0] || null,
    error:   res.locals.error[0]   || null
  });
});

app.get("/", (req, res) => {
  res.render("Login", {
    success: res.locals.success[0] || null,
    error:   res.locals.error[0]   || null
  });
});

// ── FORGOT PASSWORD PAGE ──
app.get("/forgot-password", (req, res) => {
  res.render("forgotPassword", {
    success: res.locals.success[0] || null,
    error:   res.locals.error[0]   || null
  });
});

// ── FORGOT PASSWORD POST ──
app.post("/forgot-password", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email || !validator.isEmail(email)) {
      req.flash("error", "Please enter a valid email address");
      return req.session.save(() => res.redirect("/forgot-password"));
    }

    const user = await User.findOne({ email });

    if (!user) {
      req.flash("success", "If that email exists, a reset link has been sent");
      return req.session.save(() => res.redirect("/forgot-password"));
    }

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 1000 * 60 * 30; // 30 minutes

    user.resetPasswordToken   = token;
    user.resetPasswordExpires = new Date(expires);
    await user.save();

    const resetLink = `${process.env.APP_URL}/reset-password/${token}`;

    const emailHTML = `
      <div style="font-family:Arial,sans-serif;background:#f4f6f9;padding:30px;">
        <div style="max-width:600px;margin:auto;background:white;border-radius:12px;overflow:hidden;">
          <div style="background:#1e293b;color:white;padding:20px 24px;">
            <h2 style="margin:0;">Password Reset Request</h2>
          </div>
          <div style="padding:28px 24px;">
            <p>Hello <strong>${user.name}</strong>,</p>
            <p>You requested a password reset. Click the button below to set a new password.</p>
            <p>This link expires in <strong>30 minutes</strong>.</p>
            <div style="text-align:center;margin:30px 0;">
              <a href="${resetLink}"
                style="background:#3b82f6;color:white;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;">
                Reset Password
              </a>
            </div>
            <p style="font-size:13px;color:#94a3b8;">
              If you did not request this, ignore this email. Your password will not change.
            </p>
          </div>
          <div style="background:#f8fafc;padding:16px;text-align:center;font-size:12px;color:#94a3b8;">
            © ${new Date().getFullYear()} PMS
          </div>
        </div>
      </div>
    `;

    await transporter.sendMail({
      from:    `"PMS System" <${process.env.EMAIL_USER}>`,
      to:      user.email,
      subject: "Password Reset Link",
      html:    emailHTML
    });

    req.flash("success", "If that email exists, a reset link has been sent");
    return req.session.save(() => res.redirect("/forgot-password"));

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong. Try again.");
    return req.session.save(() => res.redirect("/forgot-password"));
  }
});

// ── RESET PASSWORD PAGE ──
app.get("/reset-password/:token", async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken:   req.params.token,
      resetPasswordExpires: { $gt: new Date() }
    });

    if (!user) {
      req.flash("error", "Reset link is invalid or has expired");
      return req.session.save(() => res.redirect("/forgot-password"));
    }

    res.render("resetPassword", {
      token:   req.params.token,
      success: null,
      error:   null
    });

  } catch (err) {
    console.error(err);
    res.redirect("/forgot-password");
  }
});

// ── RESET PASSWORD POST ──
app.post("/reset-password/:token", async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken:   req.params.token,
      resetPasswordExpires: { $gt: new Date() }
    });

    if (!user) {
      req.flash("error", "Reset link is invalid or has expired");
      return req.session.save(() => res.redirect("/forgot-password"));
    }

    const newPassword     = req.body.newPassword?.trim();
    const confirmPassword = req.body.confirmPassword?.trim();

    if (!newPassword || !confirmPassword) {
      return res.render("resetPassword", {
        token:   req.params.token,
        error:   "Both fields are required",
        success: null
      });
    }

    if (newPassword.length < 6) {
      return res.render("resetPassword", {
        token:   req.params.token,
        error:   "Password must be at least 6 characters",
        success: null
      });
    }

    if (newPassword !== confirmPassword) {
      return res.render("resetPassword", {
        token:   req.params.token,
        error:   "Passwords do not match",
        success: null
      });
    }

    user.password             = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken   = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    req.flash("success", "Password reset successful. Please login.");
    return req.session.save(() => res.redirect("/login"));

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong. Try again.");
    return req.session.save(() => res.redirect("/forgot-password"));
  }
});

// ── DOCTOR DUTY — doctors only ──
app.get("/doctor/duty", allow("doctor"), async (req, res) => {
  res.render("doctorDuty", {
    name: req.session.name
  });
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const email    = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!email || !password) {
      req.flash("error", "Please enter email and password");
      return res.redirect("/login");
    }

    if (!validator.isEmail(email)) {
      req.flash("error", "Invalid email or password");
      return res.redirect("/login");
    }

    const user = await User.findOne({ email });

    if (!user) {
      req.flash("error", "Invalid email or password");
      return res.redirect("/login");
    }

    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      req.flash("error", `Account locked. Try again in ${minutesLeft} minute(s).`);
      return res.redirect("/login");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      user.loginAttempts += 1;

      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
        await user.save();
        req.flash("error", "Too many failed attempts. Account locked for 15 minutes.");
        return res.redirect("/login");
      }

      await user.save();
      req.flash("error", `Invalid credentials. Attempt ${user.loginAttempts}/5`);
      return res.redirect("/login");
    }

    user.loginAttempts = 0;
    user.lockUntil     = undefined;
    await user.save();

    req.session.userId = user._id;
    req.session.role   = user.role;
    req.session.name   = user.name;

    req.flash("success", "Welcome back!");

    if (user.role === "doctor") {
      const stillOnDuty = user.onDuty && user.dutyEndsAt && user.dutyEndsAt > new Date();
      if (stillOnDuty) {
        return res.redirect("/queue");
      } else {
        return res.redirect("/doctor/duty");
      }
    } else {
      return res.redirect("/dashboard");
    }

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    return res.redirect("/login");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Logout error:", err);
    res.clearCookie("connect.sid");
    return res.redirect("/login");
  });
});

app.post("/doctor/duty", allow("doctor"), async (req, res) => {
  try {
    const raw      = req.body.onDuty;
    const isOnDuty = String(raw).toLowerCase() === "yes";

    const doctor = await User.findById(req.session.userId);

    if (!doctor) {
      return res.redirect("/login");
    }

    if (isOnDuty) {
      doctor.onDuty        = true;
      doctor.dutyStartedAt = new Date();
      doctor.dutyEndsAt    = new Date(Date.now() + 9 * 60 * 60 * 1000);
    } else {
      doctor.onDuty        = false;
      doctor.dutyStartedAt = null;
      doctor.dutyEndsAt    = null;
    }

    await doctor.save();
    return res.redirect("/queue");

  } catch (err) {
    console.error(err);
    res.redirect("/login");
  }
});

// ── DASHBOARD — everyone ──
app.get("/dashboard", isLoggedIn, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const totalPatients   = await Patient.countDocuments();
    const todaysVisits    = await Visit.countDocuments({ createdAt: { $gte: today } });
    const totalDoctors    = await User.countDocuments({ role: "doctor" });
    const totalNurses     = await User.countDocuments({ role: "nurse" });
    const doctorsOnDuty   = await User.countDocuments({ role: "doctor", onDuty: true, dutyEndsAt: { $gt: new Date() } });
    const pendingCases    = await Visit.countDocuments({ status: { $in: ["waiting", "in-progress"] } });
    const labPending      = await Visit.countDocuments({ status: "lab" });
    const labComplete     = await Visit.countDocuments({ status: "lab-complete" });
    const waitingCount    = await Visit.countDocuments({ status: "waiting" });
    const inProgressCount = await Visit.countDocuments({ status: "in-progress" });
    const completedToday  = await Visit.countDocuments({ status: "completed", createdAt: { $gte: today } });

    const recentVisits = await Visit.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate("patient", "name")
      .populate("doctor", "name");

    const recentPatients = await Patient.find()
      .sort({ createdAt: -1 })
      .limit(5);

    const onDutyDoctors = await User.find({
      role:       "doctor",
      onDuty:     true,
      dutyEndsAt: { $gt: new Date() }
    }).select("name department dutyEndsAt");

    res.render("dashboard", {
      name: req.session.name,
      role: req.session.role,
      totalPatients,
      todaysVisits,
      totalDoctors,
      totalNurses,
      doctorsOnDuty,
      pendingCases,
      labPending,
      labComplete,
      recentVisits,
      recentPatients,
      onDutyDoctors,
      waitingCount,
      inProgressCount,
      completedToday,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    res.redirect("/login");
  }
});

app.get("/register", (req, res) => {
  res.render("SignIn");
});

// ── DOCTORS LIST — admin only ──
app.get("/doctors", allow("admin"), async (req, res) => {
  try {
    const doctors = await User.find({ role: "doctor" });
    res.render("doctor", { doctors, name: req.session.name, role: req.session.role });
  } catch (err) {
    console.error(err);
    res.send("Error loading doctors");
  }
});

// ── STAFF PROFILE — admin only ──
app.get("/staff/:id", allow("admin"), async (req, res) => {
  try {
    const staff = await User.findById(req.params.id)
      .populate("editedBy", "name role");

    if (!staff) {
      req.flash("error", "Staff not found");
      return res.redirect("/doctors");
    }

    res.render("staffProfile", {
      staff,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    res.redirect("/doctors");
  }
});

// ── EDIT STAFF — admin only ──
app.get("/staff/edit/:id", allow("admin"), async (req, res) => {
  try {
    const staff = await User.findById(req.params.id);

    if (!staff) {
      req.flash("error", "Staff member not found");
      return res.redirect("/doctors");
    }

    res.render("editStaff", {
      staff,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading edit page");
    res.redirect("/doctors");
  }
});

// ── UPDATE STAFF — admin only ──
app.post("/staff/:id/update", allow("admin"), async (req, res) => {
  try {
    const name             = sanitizeInput(req.body.name);
    const email            = req.body.email?.trim().toLowerCase();
    const phone            = sanitizeInput(req.body.phone);
    const dob              = sanitizeInput(req.body.dob);
    const gender           = sanitizeInput(req.body.gender);
    const department       = sanitizeInput(req.body.department);
    const address          = sanitizeInput(req.body.address);
    const emergencyContact = sanitizeInput(req.body.emergencyContact);

    if (!name || !email) {
      req.flash("error", "Name and email are required");
      return res.redirect(`/staff/edit/${req.params.id}`);
    }

    if (!validator.isEmail(email)) {
      req.flash("error", "Please enter a valid email");
      return res.redirect(`/staff/edit/${req.params.id}`);
    }

    const existingUser = await User.findOne({
      email,
      _id: { $ne: req.params.id }
    });

    if (existingUser) {
      req.flash("error", "That email is already used by another staff member");
      return res.redirect(`/staff/edit/${req.params.id}`);
    }

    await User.findByIdAndUpdate(req.params.id, {
      name,
      email,
      phone,
      dob,
      gender,
      department,
      address,
      emergencyContact,
      editedAt: new Date(),
      editedBy: req.session.userId
    });

    req.flash("success", "Profile updated successfully");
    return res.redirect(`/staff/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong. Try again.");
    return res.redirect(`/staff/edit/${req.params.id}`);
  }
});

// ── VISITS — nurse, doctor, admin ──
app.get("/visits", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const visits = await Visit.find({ createdAt: { $gte: yesterday } })
      .populate("patient", "name")
      .populate("doctor", "name")
      .sort({ createdAt: -1 });

    res.render("visit", {
      visits,
      doctorName: req.session.name,
      name:       req.session.name,
      role:       req.session.role
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading visits");
  }
});

// ── NURSES LIST — admin only ──
app.get("/nurses", allow("admin"), async (req, res) => {
  try {
    const nurses = await User.find({ role: "nurse" });
    res.render("nurses", { nurses, name: req.session.name, role: req.session.role });
  } catch (err) {
    console.error(err);
    res.send("Error loading nurses");
  }
});

// ── PATIENT RECORDS — nurse, doctor, admin ──
app.get("/records", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const patients = await Patient.find().sort({ createdAt: -1 });
    res.render("patient", {
      patients,
      doctorName: "Admin",
      name:       req.session.name,
      role:       req.session.role
    });
  } catch (err) {
    console.error(err);
    res.send("Error loading patients");
  }
});

// ── ADD STAFF — admin only ──
app.post("/addstaff", allow("admin"), async (req, res) => {
  try {
    const name             = sanitizeInput(req.body.name);
    const email            = req.body.email?.trim().toLowerCase();
    const phone            = sanitizeInput(req.body.phone);
    const dob              = sanitizeInput(req.body.dob);
    const gender           = sanitizeInput(req.body.gender);
    const address          = sanitizeInput(req.body.address);
    const emergencyContact = sanitizeInput(req.body.emergencyContact);
    const role             = sanitizeInput(req.body.role);
    const department       = sanitizeInput(req.body.department);

    if (!name || !email || !role) {
      req.flash("error", "Please fill all required fields");
      return res.redirect("/settings");
    }

    if (!validator.isEmail(email)) {
      req.flash("error", "Please enter a valid email address");
      return res.redirect("/settings");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash("error", "User already exists");
      return res.redirect("/settings");
    }

    const tempPassword   = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(tempPassword, 10);
    const staffID        = "STF" + Math.floor(1000 + Math.random() * 9000);

    const newUser = new User({
      name,
      email,
      phone,
      dob,
      gender,
      address,
      emergencyContact,
      role,
      department,
      staffID,
      password: hashedPassword
    });

    await newUser.save();

    const emailHTML = `
      <div style="font-family:Arial,sans-serif;background:#f4f6f9;padding:20px;">
        <div style="max-width:600px;margin:auto;background:white;border-radius:10px;overflow:hidden;">
          <div style="background:#1e293b;color:white;padding:15px;text-align:center;">
            <h2 style="margin:0;">Hospital Management System</h2>
          </div>
          <div style="padding:20px;">
            <h3>Hello ${name},</h3>
            <p>You have been added as a <strong>${role}</strong>.</p>
            <div style="background:#f1f5f9;padding:15px;border-radius:8px;">
              <p><strong>Staff ID:</strong> ${staffID}</p>
              <p><strong>Email:</strong> ${email}</p>
              <p><strong>Password:</strong> ${tempPassword}</p>
            </div>
            <p>Please login and change your password.</p>
            <div style="text-align:center;margin-top:20px;">
              <a href="${process.env.APP_URL}/login"
                style="background:#3b82f6;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;">
                Login
              </a>
            </div>
          </div>
          <div style="text-align:center;padding:10px;font-size:12px;color:#666;">
            © ${new Date().getFullYear()} PMS
          </div>
        </div>
      </div>
    `;

    await transporter.sendMail({
      from:    `"PMS System" <${process.env.EMAIL_USER}>`,
      to:      email,
      subject: "Your Staff Account",
      html:    emailHTML
    });

    req.flash("success", "Staff created successfully. Login details sent via email.");
    return res.redirect("/settings");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong. Try again.");
    return res.redirect("/settings");
  }
});

// ── CHANGE PASSWORD — everyone ──
app.post("/change-password", isLoggedIn, async (req, res) => {
  try {
    const currentPassword = req.body.currentPassword?.trim();
    const newPassword     = req.body.newPassword?.trim();
    const confirmPassword = req.body.confirmPassword?.trim();

    if (!currentPassword || !newPassword || !confirmPassword) {
      req.flash("error", "All fields are required");
      return req.session.save(() => res.redirect("/settings"));
    }

    if (newPassword.length < 6) {
      req.flash("error", "Password must be at least 6 characters");
      return req.session.save(() => res.redirect("/settings"));
    }

    if (newPassword !== confirmPassword) {
      req.flash("error", "New password and confirmation password do not match");
      return req.session.save(() => res.redirect("/settings"));
    }

    const user = await User.findById(req.session.userId);

    if (!user) {
      req.flash("error", "User not found");
      return req.session.save(() => res.redirect("/login"));
    }

    const correctPassword = await bcrypt.compare(currentPassword, user.password);

    if (!correctPassword) {
      req.flash("error", "Current password is incorrect");
      return req.session.save(() => res.redirect("/settings"));
    }

    const samePassword = await bcrypt.compare(newPassword, user.password);

    if (samePassword) {
      req.flash("error", "New password must be different from current password");
      return req.session.save(() => res.redirect("/settings"));
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    req.flash("success", "Password changed successfully");
    return req.session.save(() => res.redirect("/settings"));

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    return req.session.save(() => res.redirect("/settings"));
  }
});

// ── ADD PATIENT PAGE — nurse, admin ──
app.get("/addpa", allow("nurse", "admin"), async (req, res) => {
  const doctors = await User.find({
    role:       "doctor",
    onDuty:     true,
    dutyEndsAt: { $gt: new Date() }
  });

  res.render("addpa", {
    doctors,
    role:    req.session.role,
    success: req.flash("success"),
    error:   req.flash("error")
  });
});

// ── ADD PATIENT POST — nurse, admin ──
app.post("/addpa", allow("nurse", "admin"), async (req, res) => {
  try {
    const name             = sanitizeInput(req.body.name);
    const DOB              = sanitizeInput(req.body.DOB);
    const gender           = sanitizeInput(req.body.gender);
    const number           = sanitizeInput(req.body.number);
    const email            = req.body.email?.trim().toLowerCase() || "";
    const address          = sanitizeInput(req.body.address);
    const emergencyContact = sanitizeInput(req.body.emergencyContact);
    const nextOfKin        = sanitizeInput(req.body.nextOfKin);
    const occupation       = sanitizeInput(req.body.occupation);
    const maritalStatus    = sanitizeInput(req.body.maritalStatus);
    const insurance        = sanitizeInput(req.body.insurance);
    const insuranceNumber  = sanitizeInput(req.body.insuranceNumber);
    const bloodType        = sanitizeInput(req.body.bloodType);
    const allergies        = sanitizeInput(req.body.allergies);
    const doctor           = req.body.doctor;

    const temperature     = sanitizeInput(req.body.temperature);
    const bloodPressure   = sanitizeInput(req.body.bloodPressure);
    const heartRate       = sanitizeInput(req.body.heartRate);
    const respiratoryRate = sanitizeInput(req.body.respiratoryRate);
    const weight          = sanitizeInput(req.body.weight);
    const height          = sanitizeInput(req.body.height);

    if (email && !validator.isEmail(email)) {
      req.flash("error", "Please enter a valid email address");
      return res.redirect("/addpa");
    }

    if (!name || !DOB || !gender || !number || !address || !emergencyContact) {
      req.flash("error", "Please fill all required fields");
      return res.redirect("/addpa");
    }

    if (!temperature || !bloodPressure || !heartRate || !respiratoryRate || !weight || !height) {
      req.flash("error", "Please input all vitals before saving patient");
      return res.redirect("/addpa");
    }

    const patientID = "PAT" + Math.floor(100000 + Math.random() * 900000);

    const newPatient = new Patient({
      name,
      patientID,
      DOB,
      gender,
      number,
      email,
      address,
      emergencyContact,
      nextOfKin,
      occupation,
      maritalStatus,
      insurance,
      insuranceNumber,
      bloodType,
      allergies,
      createdBy: req.session.userId
    });

    await newPatient.save();

    const newVisit = new Visit({
      patient: newPatient._id,
      doctor:  doctor || null,
      vitals: {
        temperature,
        bloodPressure,
        heartRate,
        respiratoryRate,
        weight,
        height
      },
      status: "waiting",
      nurse:  req.session.userId
    });

    await newVisit.save();

    req.flash("success", "Patient added and added to queue");
    res.redirect("/records");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/addpa");
  }
});

// ── EDIT PATIENT — nurse, doctor, admin ──
app.post("/patient/:id/edit", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    await Patient.findByIdAndUpdate(
      req.params.id,
      {
        name:             sanitizeInput(req.body.name),
        DOB:              sanitizeInput(req.body.DOB),
        gender:           sanitizeInput(req.body.gender),
        number:           sanitizeInput(req.body.number),
        email:            req.body.email?.trim().toLowerCase(),
        address:          sanitizeInput(req.body.address),
        emergencyContact: sanitizeInput(req.body.emergencyContact)
      }
    );

    req.flash("success", "Patient information updated");
    res.redirect(`/patient/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Failed to update patient");
    res.redirect(`/patient/${req.params.id}`);
  }
});

// ── REGISTER NEW PATIENT + ADMIT — nurse, admin ──
app.post("/addpa-admit", allow("nurse", "admin"), async (req, res) => {
  try {
    const name             = sanitizeInput(req.body.name);
    const DOB              = sanitizeInput(req.body.DOB);
    const gender           = sanitizeInput(req.body.gender);
    const number           = sanitizeInput(req.body.number);
    const email            = req.body.email?.trim().toLowerCase() || "";
    const address          = sanitizeInput(req.body.address);
    const emergencyContact = sanitizeInput(req.body.emergencyContact);
    const nextOfKin        = sanitizeInput(req.body.nextOfKin);
    const occupation       = sanitizeInput(req.body.occupation);
    const maritalStatus    = sanitizeInput(req.body.maritalStatus);
    const insurance        = sanitizeInput(req.body.insurance);
    const insuranceNumber  = sanitizeInput(req.body.insuranceNumber);
    const doctor           = req.body.doctor;

    const temperature     = sanitizeInput(req.body.temperature);
    const bloodPressure   = sanitizeInput(req.body.bloodPressure);
    const heartRate       = sanitizeInput(req.body.heartRate);
    const respiratoryRate = sanitizeInput(req.body.respiratoryRate);
    const weight          = sanitizeInput(req.body.weight);
    const height          = sanitizeInput(req.body.height);

    const admissionReason = sanitizeInput(req.body.admissionReason);
    const ward            = sanitizeInput(req.body.ward);
    const bed             = sanitizeInput(req.body.bed);
    const admitStatus     = sanitizeInput(req.body.admitStatus);

    if (!name || !DOB || !gender || !number || !address || !emergencyContact) {
      req.flash("error", "Please fill all required patient fields");
      return res.redirect("/addpa");
    }

    if (email && !validator.isEmail(email)) {
      req.flash("error", "Please enter a valid email address");
      return res.redirect("/addpa");
    }

    if (!admissionReason || !ward) {
      req.flash("error", "Admission reason and ward are required");
      return res.redirect("/addpa");
    }

    const patientID  = "PAT" + Math.floor(100000 + Math.random() * 900000);

    const newPatient = new Patient({
      name,
      patientID,
      DOB,
      gender,
      number,
      email,
      address,
      emergencyContact,
      nextOfKin,
      occupation,
      maritalStatus,
      insurance,
      insuranceNumber,
      createdBy: req.session.userId
    });
    await newPatient.save();

    const newVisit = new Visit({
      patient: newPatient._id,
      doctor:  doctor || null,
      vitals: {
        temperature,
        bloodPressure,
        heartRate,
        respiratoryRate,
        weight,
        height
      },
      status: "admitted",
      nurse:  req.session.userId
    });
    await newVisit.save();

    const newAdmission = new Admission({
      patient:         newPatient._id,
      admittedBy:      req.session.userId,
      admissionReason,
      ward,
      bed,
      status:      admitStatus || "observation",
      isEmergency: false
    });
    await newAdmission.save();

    req.flash("success", "Patient registered and admitted successfully");
    return res.redirect(`/admitted/${newAdmission._id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    return res.redirect("/addpa");
  }
});

// ── PATIENT PROFILE — nurse, doctor, admin ──
app.get("/patient/:id", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id)
      .populate("createdBy", "name role");

    if (!patient) {
      return res.status(404).send("Patient not found");
    }

    const visits = await Visit.find({ patient: patient._id })
      .sort({ createdAt: -1 })
      .populate("nurse", "name")
      .populate("doctor", "name");

    const admissions = await Admission.find({ patient: patient._id })
      .populate("admittedBy", "name")
      .populate("dischargedBy", "name")
      .populate("wardRounds.addedBy", "name")
      .populate("medications.addedBy", "name")
      .populate("medications.removedBy", "name")
      .populate("labRequests")
      .sort({ admittedAt: -1 });

    res.render("patientProfile", {
      patient,
      nurse:      patient.createdBy,
      visits:     visits || [],
      admissions: admissions || [],
      doctorName: req.session.name,
      role:       req.session.role,
      success:    req.flash("success"),
      error:      req.flash("error")
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading patient");
  }
});

// ── QUEUE — doctor only ──
app.get("/queue", allow("doctor"), async (req, res) => {
  try {
    let query = {
      status: { $in: ["waiting", "lab", "lab-complete"] }
    };

    if (req.session.role === "doctor") {
      query.doctor = req.session.userId;
    }

    const visits = await Visit.find(query)
      .populate("patient")
      .sort({ createdAt: 1 });

    const currentUser = await User.findById(req.session.userId);

    const waiting     = visits.filter(v => v.status === "waiting");
    const lab         = visits.filter(v => v.status === "lab");
    const labComplete = visits.filter(v => v.status === "lab-complete");

    let shiftWarning = null;

    if (currentUser && currentUser.role === "doctor" && currentUser.dutyEndsAt) {
      const msLeft      = new Date(currentUser.dutyEndsAt).getTime() - Date.now();
      const minutesLeft = Math.floor(msLeft / 60000);

      if (minutesLeft <= 30 && minutesLeft > 0) {
        shiftWarning = `Your shift ends in ${minutesLeft} minute(s). Logout and login again if you wish to continue working.`;
      }

      if (minutesLeft <= 0) {
        currentUser.onDuty        = false;
        currentUser.dutyStartedAt = null;
        currentUser.dutyEndsAt    = null;
        await currentUser.save();
        shiftWarning = `❌ Your shift has ended. Please logout and login again if you are still on duty.`;
      }
    }

    res.render("queue", {
      waiting,
      lab,
      labComplete,
      name:        req.session.name,
      role:        req.session.role,
      shiftWarning
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading queue");
  }
});

// ── NEW VISIT PAGE — nurse, admin ──
app.get("/visit/new/:id", allow("nurse", "admin"), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);

    if (!patient) {
      req.flash("error", "Patient not found");
      return res.redirect("/records");
    }

    const doctors = await User.find({
      role:       "doctor",
      onDuty:     true,
      dutyEndsAt: { $gt: new Date() }
    });

    res.render("addVisit", {
      patient,
      doctors,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading page");
  }
});

// ── ADD VISIT POST — nurse, admin ──
app.post("/add-visit/:id", allow("nurse", "admin"), async (req, res) => {
  try {
    const patientId = req.params.id;

    const temperature     = sanitizeInput(req.body.temperature);
    const bloodPressure   = sanitizeInput(req.body.bloodPressure);
    const heartRate       = sanitizeInput(req.body.heartRate);
    const respiratoryRate = sanitizeInput(req.body.respiratoryRate);
    const weight          = sanitizeInput(req.body.weight);
    const height          = sanitizeInput(req.body.height);
    const notes           = sanitizeInput(req.body.notes);
    const doctor          = req.body.doctor;

    if (!temperature || !bloodPressure || !heartRate || !respiratoryRate || !weight || !height || !doctor) {
      req.flash("error", "Vitals and doctor are required");
      return res.redirect(`/visit/new/${patientId}`);
    }

    const newVisit = new Visit({
      patient: patientId,
      vitals: {
        temperature,
        bloodPressure,
        heartRate,
        respiratoryRate,
        weight,
        height
      },
      notes,
      doctor,
      status: "waiting",
      nurse:  req.session.userId
    });

    await newVisit.save();

    req.flash("success", "Visit added and sent to queue");
    res.redirect(`/patient/${patientId}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("back");
  }
});

// ── ADMIT EXISTING PATIENT — nurse, admin ──
app.post("/admit-direct/:patientId", allow("nurse", "admin"), async (req, res) => {
  try {
    const patientId = req.params.patientId;

    const temperature     = sanitizeInput(req.body.temperature);
    const bloodPressure   = sanitizeInput(req.body.bloodPressure);
    const heartRate       = sanitizeInput(req.body.heartRate);
    const respiratoryRate = sanitizeInput(req.body.respiratoryRate);
    const weight          = sanitizeInput(req.body.weight);
    const height          = sanitizeInput(req.body.height);
    const notes           = sanitizeInput(req.body.notes);
    const doctor          = req.body.doctor;

    const admissionReason = sanitizeInput(req.body.admissionReason);
    const ward            = sanitizeInput(req.body.ward);
    const bed             = sanitizeInput(req.body.bed);
    const admitStatus     = sanitizeInput(req.body.admitStatus);

    if (!temperature || !bloodPressure || !heartRate || !respiratoryRate || !weight || !height) {
      req.flash("error", "Please fill in all vitals before admitting");
      return res.redirect(`/visit/new/${patientId}`);
    }

    if (!admissionReason || !ward) {
      req.flash("error", "Admission reason and ward are required");
      return res.redirect(`/visit/new/${patientId}`);
    }

    const newVisit = new Visit({
      patient: patientId,
      vitals: {
        temperature,
        bloodPressure,
        heartRate,
        respiratoryRate,
        weight,
        height
      },
      notes,
      doctor: doctor || null,
      status: "admitted",
      nurse:  req.session.userId
    });
    await newVisit.save();

    const newAdmission = new Admission({
      patient:         patientId,
      admittedBy:      req.session.userId,
      admissionReason,
      ward,
      bed,
      status:      admitStatus || "observation",
      isEmergency: false
    });
    await newAdmission.save();

    req.flash("success", "Patient admitted successfully");
    return res.redirect(`/admitted/${newAdmission._id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong during admission");
    return res.redirect(`/visit/new/${req.params.patientId}`);
  }
});

// ── DOCTOR CONSULTATION PAGE — doctor only ──
app.get("/visit/:id/doctor", allow("doctor"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.id)
      .populate("patient")
      .populate("nurse", "name");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/queue");
    }

    if (!visit.doctor) {
      visit.doctor = req.session.userId;
      await visit.save();
    }

    if (visit.status === "waiting") {
      visit.status = "in-progress";
      await visit.save();
    }

    const visits = await Visit.find({ patient: visit.patient._id })
      .sort({ createdAt: -1 });

    const summary = generatePatientSummary(visits);

    res.render("doctorVisit", {
      visit,
      patient:    visit.patient,
      visits,
      summary,
      doctorName: req.session.name,
      role:       req.session.role
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/queue");
  }
});

// ── DOCTOR CONSULTATION POST — doctor only ──
app.post("/visit/:id/doctor", allow("doctor"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.id);

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/queue");
    }

    const complaint    = sanitizeInput(req.body.complaint);
    const observation  = sanitizeInput(req.body.observation);
    const diagnosis    = sanitizeInput(req.body.diagnosis);
    const prescription = sanitizeInput(req.body.prescription);
    const notes        = sanitizeInput(req.body.notes);
    const tests        = sanitizeInput(req.body.tests);
    const status       = sanitizeInput(req.body.status);

    visit.complaint    = complaint;
    visit.observation  = observation;
    visit.diagnosis    = diagnosis;
    visit.prescription = prescription;
    visit.notes        = notes;
    visit.tests        = tests;
    visit.doctor       = req.session.userId;

    if (status === "lab") {
      visit.status  = "lab";
      visit.labType = "internal";
    } else if (status === "completed") {
      visit.status = "completed";
    } else {
      if (visit.status !== "lab-complete") {
        visit.status = "in-progress";
      }
    }

    await visit.save();

    req.flash("success", "Visit updated successfully");
    return res.redirect("/queue");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("back");
  }
});

// ── EXTERNAL LAB — doctor only ──
app.post("/visit/:id/external-lab", allow("doctor"), async (req, res) => {
  try {
    const { externalLabName, tests, complaint, observation, diagnosis, prescription, notes } = req.body;

    const visit = await Visit.findById(req.params.id).populate("patient");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/queue");
    }

    visit.complaint    = sanitizeInput(complaint);
    visit.observation  = sanitizeInput(observation);
    visit.tests        = sanitizeInput(tests);
    visit.diagnosis    = sanitizeInput(diagnosis);
    visit.prescription = sanitizeInput(prescription);
    visit.notes        = sanitizeInput(notes);

    visit.status            = "lab";
    visit.labType           = "external";
    visit.externalLabStatus = "pending";
    visit.externalLabName   = sanitizeInput(externalLabName);
    visit.externalLabSentAt = new Date();
    visit.doctor            = req.session.userId;

    await visit.save();

    const patient   = visit.patient;
    const sentDate  = new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
    const sentTime  = new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    const testsText = tests || "as instructed by your doctor";

    if (patient.email) {
      try {
        const emailHTML = `
          <div style="font-family:Arial,sans-serif;background:#f4f6f9;padding:30px;">
            <div style="max-width:600px;margin:auto;background:white;border-radius:12px;overflow:hidden;">
              <div style="background:#1e293b;color:white;padding:20px 24px;">
                <h2 style="margin:0;font-size:20px;">Hospital Management System</h2>
                <p style="margin:6px 0 0;font-size:13px;color:#94a3b8;">Lab Referral Notice</p>
              </div>
              <div style="padding:28px 24px;">
                <p style="font-size:15px;color:#0f172a;">Hello <strong>${patient.name}</strong>,</p>
                <p style="font-size:14px;color:#475569;line-height:1.7;">
                  Your doctor has referred you for laboratory tests.
                </p>
                <div style="background:#f8fafc;border-radius:10px;padding:18px;border-left:4px solid #3b82f6;margin:20px 0;">
                  <table style="width:100%;border-collapse:collapse;font-size:14px;">
                    <tr>
                      <td style="padding:7px 0;color:#64748b;width:140px;">Date Issued</td>
                      <td style="padding:7px 0;color:#0f172a;font-weight:600;">${sentDate} at ${sentTime}</td>
                    </tr>
                    <tr>
                      <td style="padding:7px 0;color:#64748b;">Patient Name</td>
                      <td style="padding:7px 0;color:#0f172a;font-weight:600;">${patient.name}</td>
                    </tr>
                    <tr>
                      <td style="padding:7px 0;color:#64748b;">Patient ID</td>
                      <td style="padding:7px 0;color:#0f172a;font-weight:600;">${patient.patientID}</td>
                    </tr>
                    <tr>
                      <td style="padding:7px 0;color:#64748b;">Tests Required</td>
                      <td style="padding:7px 0;color:#0f172a;font-weight:600;">${testsText}</td>
                    </tr>
                  </table>
                </div>
                <div style="background:#fef9c3;border-radius:10px;padding:16px;margin:20px 0;">
                  <p style="margin:0;font-size:14px;color:#92400e;">
                    <strong>📋 Instructions</strong><br><br>
                    Please proceed to your preferred laboratory. Once completed,
                    <strong>return to the hospital with your results</strong>.
                  </p>
                </div>
              </div>
              <div style="background:#f8fafc;padding:16px 24px;text-align:center;font-size:12px;color:#94a3b8;">
                © ${new Date().getFullYear()} Hospital Management System
              </div>
            </div>
          </div>
        `;

        await transporter.sendMail({
          from:    `"Hospital Management System" <${process.env.EMAIL_USER}>`,
          to:      patient.email,
          subject: `Lab Referral — ${testsText}`,
          html:    emailHTML
        });

      } catch (emailErr) {
        console.error("Email failed (non-critical):", emailErr.message);
      }
    }

    req.flash("success", "Patient referred to external lab. Notification sent.");
    return res.redirect("/queue");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    return res.redirect("/queue");
  }
});

// ── RESUME EXTERNAL LAB — nurse, admin ──
app.post("/visit/:id/resume-external", allow("nurse", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.id).populate("patient");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/records");
    }

    visit.complaint    = req.body.complaint    || visit.complaint;
    visit.observation  = req.body.observation  || visit.observation;
    visit.diagnosis    = req.body.diagnosis    || visit.diagnosis;
    visit.prescription = req.body.prescription || visit.prescription;
    visit.notes        = req.body.notes        || visit.notes;
    visit.tests        = req.body.tests        || visit.tests;

    visit.externalLabStatus      = "completed";
    visit.externalLabCompletedAt = new Date();
    visit.status                 = "lab-complete";
    visit.labCompletedAt         = new Date();
    visit.labCompletedBy         = req.session.userId;

    await visit.save();

    req.flash("success", "Results marked as returned. Visit is now in the lab results queue for the doctor.");
    return res.redirect(`/patient/${visit.patient._id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("back");
  }
});

// ── SETTINGS — everyone ──
app.get("/settings", isLoggedIn, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);

    res.render("settings", {
      name:       req.session.name,
      role:       user.role,
      staffID:    user.staffID,
      department: user.department,
      email:      user.email,
      success:    res.locals.success[0] || null,
      error:      res.locals.error[0]   || null
    });

  } catch (err) {
    console.error(err);
    res.redirect("/dashboard");
  }
});

// ── LAB PAGE — lab only ──
app.get("/lab", allow("lab"), async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const pending = await Visit.find({ status: "lab", labType: { $ne: "external" } })
      .populate("patient", "name patientID")
      .populate("doctor", "name")
      .sort({ createdAt: 1 });

    const completed = await Visit.find({
      status:         "lab-complete",
      labCompletedAt: { $gte: today },
      labType:        { $ne: "external" }
    })
      .populate("patient", "name patientID")
      .populate("doctor", "name")
      .sort({ labCompletedAt: -1 });

    res.render("lab", {
      pending,
      completed,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading lab page");
    res.redirect("/dashboard");
  }
});

// ── LAB UPLOAD — lab only ──
app.post(
  "/lab/upload",
  allow("lab"),
  upload.single("labReport"),

  async (req, res, next) => {
    try {
      const token = req.body._csrf;

      if (!req.session.csrfSecret) {
        req.flash("error", "Invalid request.");
        return res.redirect("/lab");
      }

      if (!token) {
        req.flash("error", "Missing CSRF token.");
        return res.redirect("/lab");
      }

      if (!tokens.verify(req.session.csrfSecret, token)) {
        req.flash("error", "Invalid CSRF token.");
        return res.redirect("/lab");
      }

      next();

    } catch (err) {
      console.error(err);
      req.flash("error", "Security validation failed.");
      return res.redirect("/lab");
    }
  },

  async (req, res) => {
    try {
      const visitId    = sanitizeInput(req.body.visitId);
      const labResults = sanitizeInput(req.body.labResults);

      if (!visitId || !labResults) {
        req.flash("error", "Results are required");
        return res.redirect("/lab");
      }

      const visit = await Visit.findById(visitId);

      if (!visit) {
        req.flash("error", "Visit not found");
        return res.redirect("/lab");
      }

      visit.labResults = labResults;

      if (req.file) {
        visit.labResult = "uploads/lab/" + req.file.filename;
      }

      visit.status            = "lab-complete";
      visit.externalLabStatus = "completed";
      visit.labCompletedAt    = new Date();
      visit.labCompletedBy    = req.session.userId;

      await visit.save();

      req.flash("success", "Lab results uploaded successfully.");
      return res.redirect("/lab");

    } catch (err) {
      console.error(err);
      req.flash("error", "Something went wrong uploading results");
      return res.redirect("/lab");
    }
  }
);

// ── ADMITTED LIST — nurse, doctor, admin ──
app.get("/admitted", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const admissions = await Admission.find({ isActive: true })
      .populate("patient", "name patientID gender number bloodType allergies emergencyContact")
      .populate("admittedBy", "name")
      .sort({ admittedAt: -1 });

    res.render("admitted", {
      admissions,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading admitted patients");
    res.redirect("/dashboard");
  }
});

// ── ADMITTED PROFILE — nurse, doctor, admin ──
app.get("/admitted/:id", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const admission = await Admission.findById(req.params.id)
      .populate("patient")
      .populate("admittedBy", "name")
      .populate("wardRounds.addedBy", "name")
      .populate("medications.addedBy", "name")
      .populate("labRequests");

    if (!admission) {
      req.flash("error", "Admission not found");
      return res.redirect("/admitted");
    }

    res.render("admittedProfile", {
      admission,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading admission");
    res.redirect("/admitted");
  }
});

// ── ADMIT FROM DOCTOR CONSULT — doctor, admin ──
app.post("/admit/:patientId", allow("doctor", "admin"), async (req, res) => {
  try {
    const { admissionReason, ward, bed, status, visitId } = req.body;

    const newAdmission = new Admission({
      patient:         req.params.patientId,
      admittedBy:      req.session.userId,
      admissionReason,
      ward,
      bed,
      status:      status || "observation",
      isEmergency: false
    });

    await newAdmission.save();

    if (visitId) {
      await Visit.findByIdAndUpdate(visitId, { status: "admitted" });
    }

    req.flash("success", "Patient admitted successfully");
    return res.redirect(`/admitted/${newAdmission._id}`);

  } catch (err) {
    console.error(err);
    return res.send(err.message);
  }
});

// ── EMERGENCY ADMISSION — nurse, admin ──
app.post("/admit-emergency/:patientId", allow("nurse", "admin"), async (req, res) => {
  try {
    const { admissionReason, ward, bed, status } = req.body;

    const newAdmission = new Admission({
      patient:         req.params.patientId,
      admittedBy:      req.session.userId,
      admissionReason: sanitizeInput(admissionReason),
      ward:            sanitizeInput(ward),
      bed:             sanitizeInput(bed),
      status:          status || "critical",
      isEmergency:     true
    });

    await newAdmission.save();

    req.flash("success", "Patient admitted as emergency");
    return res.redirect(`/admitted/${newAdmission._id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/records");
  }
});

// ── UPDATE ADMISSION STATUS — nurse, doctor, admin ──
app.post("/admitted/:id/status", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const { status } = req.body;

    await Admission.findByIdAndUpdate(req.params.id, { status });

    req.flash("success", "Status updated");
    return res.redirect(`/admitted/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/admitted");
  }
});

// ── ADD WARD ROUND — nurse, doctor, admin ──
app.post("/admitted/:id/round", allow("nurse", "doctor", "admin"), async (req, res) => {
  try {
    const { notes, temperature, bloodPressure, heartRate, respiratoryRate, weight } = req.body;

    const admission = await Admission.findById(req.params.id);

    if (!admission) {
      req.flash("error", "Admission not found");
      return res.redirect("/admitted");
    }

    admission.wardRounds.push({
      notes:   sanitizeInput(notes),
      addedBy: req.session.userId,
      addedAt: new Date(),
      vitals: {
        temperature:     temperature     ? Number(temperature)          : undefined,
        bloodPressure:   bloodPressure   ? sanitizeInput(bloodPressure) : undefined,
        heartRate:       heartRate       ? Number(heartRate)            : undefined,
        respiratoryRate: respiratoryRate ? Number(respiratoryRate)      : undefined,
        weight:          weight          ? Number(weight)               : undefined
      }
    });

    await admission.save();

    req.flash("success", "Ward round saved");
    return res.redirect(`/admitted/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect(`/admitted/${req.params.id}`);
  }
});

// ── ADD MEDICATION — doctor, admin ──
app.post("/admitted/:id/medication", allow("doctor", "admin"), async (req, res) => {
  try {
    const { name, dosage, frequency } = req.body;

    const admission = await Admission.findById(req.params.id);

    if (!admission) {
      req.flash("error", "Admission not found");
      return res.redirect("/admitted");
    }

    admission.medications.push({
      name:      sanitizeInput(name),
      dosage:    sanitizeInput(dosage),
      frequency: sanitizeInput(frequency),
      addedBy:   req.session.userId,
      addedAt:   new Date()
    });

    await admission.save();

    req.flash("success", "Medication added");
    return res.redirect(`/admitted/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect(`/admitted/${req.params.id}`);
  }
});

// ── REMOVE MEDICATION — doctor, admin ──
app.post("/admitted/:id/medication/:medId/remove", allow("doctor", "admin"), async (req, res) => {
  try {
    const admission = await Admission.findById(req.params.id);

    if (!admission) {
      req.flash("error", "Admission not found");
      return res.redirect("/admitted");
    }

    const med = admission.medications.id(req.params.medId);

    if (!med) {
      req.flash("error", "Medication not found");
      return res.redirect(`/admitted/${req.params.id}`);
    }

    med.active    = false;
    med.removedBy = req.session.userId;
    med.removedAt = new Date();

    await admission.save();

    req.flash("success", "Medication discontinued");
    res.redirect(`/admitted/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect(`/admitted/${req.params.id}`);
  }
});

// ── LAB REQUEST FROM WARD — doctor, admin ──
app.post("/admitted/:id/lab", allow("doctor", "admin"), async (req, res) => {
  try {
    const { tests } = req.body;

    const admission = await Admission.findById(req.params.id).populate("patient");

    if (!admission) {
      req.flash("error", "Admission not found");
      return res.redirect("/admitted");
    }

    const labVisit = new Visit({
      patient: admission.patient._id,
      doctor:  req.session.userId,
      tests:   sanitizeInput(tests),
      status:  "lab",
      nurse:   req.session.userId
    });

    await labVisit.save();

    admission.labRequests.push(labVisit._id);
    await admission.save();

    req.flash("success", "Lab request sent");
    return res.redirect(`/admitted/${req.params.id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect(`/admitted/${req.params.id}`);
  }
});

// ── DISCHARGE — doctor, admin ──
app.post("/admitted/:id/discharge", allow("doctor", "admin"), async (req, res) => {
  try {
    const { dischargeNotes } = req.body;

    await Admission.findByIdAndUpdate(req.params.id, {
      status:         "discharged",
      isActive:       false,
      dischargedAt:   new Date(),
      dischargeNotes: sanitizeInput(dischargeNotes),
      dischargedBy:   req.session.userId
    });

    req.flash("success", "Patient discharged successfully");
    return res.redirect("/admitted");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect(`/admitted/${req.params.id}`);
  }
});

// ── END DUTY — doctor only ──
app.post("/doctor/duty/end", allow("doctor"), async (req, res) => {
  try {
    const doctor = await User.findById(req.session.userId);

    if (!doctor) return res.redirect("/login");

    doctor.onDuty        = false;
    doctor.dutyStartedAt = null;
    doctor.dutyEndsAt    = null;

    await doctor.save();

    req.session.destroy((err) => {
      if (err) console.error("Session destroy error:", err);
      res.clearCookie("connect.sid");
      return res.redirect("/login");
    });

  } catch (err) {
    console.error(err);
    res.redirect("/queue");
  }
});

// ── 404 ──
app.use((req, res) => {
  res.status(404).redirect("/dashboard");
});

// ── 500 ──
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).redirect("/dashboard");
});

app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});