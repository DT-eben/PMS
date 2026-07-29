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


// ── DRUG NAME MATCHING (place near your other helper functions, e.g. below sanitizeInput) ──

// Standard edit-distance algorithm: counts the minimum number of
// single-character insertions/deletions/substitutions to turn one
// string into another. "Paracetmol" vs "Paracetamol" = distance 1.
function levenshtein(a, b) {
  a = String(a).toLowerCase();
  b = String(b).toLowerCase();

  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(
          dp[i - 1][j],     // deletion
          dp[i][j - 1],     // insertion
          dp[i - 1][j - 1]  // substitution
        );
      }
    }
  }

  return dp[m][n];
}

// Defensive stringifier — never lets a non-string value reach String()
// and produce "[object Object]". Used as a safety net at the display/
// matching layer (does NOT fix already-corrupted data already saved).
function drugNameText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.filter(Boolean).join(", ");
  if (value && typeof value === "object") return Object.values(value).filter(Boolean).join(", ");
  return value == null ? "" : String(value);
}

// Resolves a (possibly mistyped) prescribed drug name against your
// inventory. Rules, deliberately conservative:
//   1. Exact case-insensitive name match always wins outright.
//   2. Otherwise, look for inventory drugs within a small edit distance
//      (1 letter for short names, 2 for longer ones).
//   3. If exactly ONE drug is that close -> treat it as a match, but
//      flag it as "fuzzy" so the UI can show it was auto-corrected.
//   4. If TWO OR MORE drugs are equally close -> refuse to guess.
//      Guessing wrong here means dispensing/pricing the wrong drug,
//      which is worse than just asking a human to check.
function resolveDrug(name, allDrugs) {
  const cleanName = drugNameText(name).trim();

  if (!cleanName) {
    return { drug: null, matchType: "none" };
  }

  const lower = cleanName.toLowerCase();

  const exact = allDrugs.find(d => d.name.toLowerCase() === lower);
  if (exact) {
    return { drug: exact, matchType: "exact" };
  }

  const maxDistance = lower.length <= 4 ? 1 : 2;

  const candidates = [];
  for (const d of allDrugs) {
    const dist = levenshtein(lower, d.name.toLowerCase());
    if (dist <= maxDistance) {
      candidates.push({ drug: d, dist });
    }
  }

  if (candidates.length === 0) {
    return { drug: null, matchType: "none" };
  }

  candidates.sort((a, b) => a.dist - b.dist);
  const bestDistance = candidates[0].dist;
  const bestMatches  = candidates.filter(c => c.dist === bestDistance);

  if (bestMatches.length === 1) {
    return { drug: bestMatches[0].drug, matchType: "fuzzy", distance: bestDistance };
  }

  // two or more equally-close candidates — too risky to auto-pick
  return { drug: null, matchType: "ambiguous" };
}


const User                  = require("./model/user");
const Patient               = require("./model/patient");
const Visit                 = require("./model/visit");
const Admission             = require("./model/admission");
const Drug                  = require("./model/drugs");
const PriceItem             = require("./model/priceItem");
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

    const complaint   = sanitizeInput(req.body.complaint);
    const observation = sanitizeInput(req.body.observation);
    const diagnosis   = sanitizeInput(req.body.diagnosis);
    const notes       = sanitizeInput(req.body.notes);
    const tests       = sanitizeInput(req.body.tests);
    const status      = sanitizeInput(req.body.status);

    // Accepts EITHER key shape:
    //  - req.body.drugName            (qs / extended:true — brackets stripped, the norm)
    //  - req.body["drugName[]"]       (raw querystring / extended:false — brackets kept)
    // Whichever one actually has data wins. This is the real fix: the old
    // code only ever checked the bracketed key, which your body parser
    // never populates, so the per-index array logic below was silently
    // never running on real data.
    function pickArrayField(bracketKey, plainKey) {
      const val = req.body[bracketKey] !== undefined ? req.body[bracketKey] : req.body[plainKey];
      return [].concat(val === undefined || val === null ? [] : val);
    }

    // Coerces ANY value (string, array, object, undefined) down to a single
    // clean string. This is the field-level backstop: even if a value ever
    // arrives as an array or object again for any reason, this guarantees
    // Mongo only ever receives readable text — never "[object Object]".
    function textOf(v) {
      if (v === undefined || v === null) return '';
      if (typeof v === 'string') return v;
      if (Array.isArray(v)) return v.filter(Boolean).join(', ');
      if (typeof v === 'object') return Object.values(v).filter(Boolean).join(', ');
      return String(v);
    }

    const drugNames    = pickArrayField("drugName[]", "drugName");
    const dosages      = pickArrayField("dosage[]", "dosage");
    const frequencies  = pickArrayField("frequency[]", "frequency");
    const durations    = pickArrayField("duration[]", "duration");
    const routes       = pickArrayField("route[]", "route");
    const drugNotesArr = pickArrayField("drugNotes[]", "drugNotes");

    const prescriptions = drugNames
      .map((name, i) => ({
        drugName:  sanitizeInput(textOf(name)),
        dosage:    sanitizeInput(textOf(dosages[i])),
        frequency: sanitizeInput(textOf(frequencies[i])),
        duration:  sanitizeInput(textOf(durations[i])),
        route:     sanitizeInput(textOf(routes[i])),
        notes:     sanitizeInput(textOf(drugNotesArr[i]))
      }))
      .filter(p => p.drugName.trim() !== '');

    visit.complaint     = complaint;
    visit.observation    = observation;
    visit.diagnosis      = diagnosis;
    visit.notes          = notes;
    visit.tests          = tests;
    visit.doctor         = req.session.userId;
    visit.prescriptions  = prescriptions;

    if (status === "lab") {
      visit.status  = "lab";
      visit.labType = "internal";
    } else if (status === "completed") {
      visit.status = prescriptions.length > 0 ? "pharmacy" : "billing";
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
    const { externalLabName, tests, complaint, observation, diagnosis, notes } = req.body;

    const visit = await Visit.findById(req.params.id).populate("patient");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/queue");
    }

    visit.complaint    = sanitizeInput(complaint);
    visit.observation  = sanitizeInput(observation);
    visit.tests        = sanitizeInput(tests);
    visit.diagnosis    = sanitizeInput(diagnosis);
    visit.notes        = sanitizeInput(notes);

    // same bracket-array parsing as /visit/:id/doctor — this form can also
    // carry prescriptions[] if the doctor filled drugs before sending externally
    const drugNames    = [].concat(req.body["drugName[]"]  || []);
    const dosages      = [].concat(req.body["dosage[]"]    || []);
    const frequencies  = [].concat(req.body["frequency[]"] || []);
    const durations    = [].concat(req.body["duration[]"]  || []);
    const routes       = [].concat(req.body["route[]"]     || []);
    const drugNotesArr = [].concat(req.body["drugNotes[]"] || []);

    const prescriptions = drugNames
      .map((name, i) => ({
        drugName:  sanitizeInput(drugNameText(name)),
        dosage:    sanitizeInput(dosages[i]),
        frequency: sanitizeInput(frequencies[i]),
        duration:  sanitizeInput(durations[i]),
        route:     sanitizeInput(routes[i]),
        notes:     sanitizeInput(drugNotesArr[i])
      }))
      .filter(p => p.drugName);

    if (prescriptions.length > 0) {
      visit.prescriptions = prescriptions;
    }

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
    visit.notes        = req.body.notes        || visit.notes;
    visit.tests        = req.body.tests        || visit.tests;
    // removed: visit.prescription = ... — that field doesn't exist on the
    // schema anymore (replaced by prescriptions[]), this route doesn't
    // collect drug rows so there's nothing to set here

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
// ── PHARMACY QUEUE — pharmacist only ──
app.get("/pharmacy", allow("pharmacist"), async (req, res) => {
  try {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    // first-come-first-serve: oldest visit at the top
    const pending = await Visit.find({ status: "pharmacy" })
      .populate("patient")
      .populate("doctor")
      .sort({ createdAt: 1 });

    const completed = await Visit.find({
      status: { $in: ["billing", "paid", "completed"] },
      pharmacyCompletedAt: { $gte: startOfDay }
    })
      .populate("patient")
      .populate("doctor")
      .sort({ pharmacyCompletedAt: -1 });

    // name -> { sellingPrice, quantityInStock } — sent to the browser so the
    // dispense modal can show price + stock status live, without the
    // pharmacist typing anything but quantity
    const allDrugs = await Drug.find({}, "name sellingPrice quantityInStock");
    const drugPriceMap = {};
    allDrugs.forEach(d => {
      drugPriceMap[d.name.toLowerCase()] = {
        sellingPrice:    d.sellingPrice,
        quantityInStock: d.quantityInStock
      };
    });

    res.render("pharmacy", {
      pending,
      completed,
      drugPriceMap,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading pharmacy queue");
  }
});

function escapeRegExp(string) {
  return String(string).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── PHARMACY DISPENSE POST — pharmacist only ──
app.post("/pharmacy/dispense", allow("pharmacist"), async (req, res) => {
  try {
    const { visitId, pharmacyNotes, drugCount } = req.body;

    const visit = await Visit.findById(visitId);
    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/pharmacy");
    }

    const count    = parseInt(drugCount) || 0;
    const allDrugs = await Drug.find(); // full docs — we mutate & save stock levels

    const dispensedDrugs  = [];
    const autoCorrected   = [];
    const shortfallDrugs  = [];
    const unavailableDrugs = [];
    let drugFee = 0;

    for (let i = 0; i < count; i++) {
      const rawName          = sanitizeInput(req.body[`drugName_${i}`]);
      const quantityRequested = parseFloat(req.body[`requestedQty_${i}`]) || 0;
      const quantitySubmitted = parseFloat(req.body[`quantity_${i}`]) || 0;

      if (!rawName) continue; // skip empty rows entirely

      const { drug: inventoryDrug, matchType } = resolveDrug(rawName, allDrugs);

      let drugNameForRecord = rawName;
      if (matchType === "fuzzy") {
        autoCorrected.push(`${rawName} → ${inventoryDrug.name}`);
        drugNameForRecord = inventoryDrug.name;
      }

      let unitCost         = 0;
      let quantityDispensed = 0;
      let totalCost         = 0;
      let outOfStock        = false;
      let notInInventory     = false;

      if (inventoryDrug) {
        unitCost = inventoryDrug.sellingPrice;
        const available = inventoryDrug.quantityInStock;

        if (available <= 0) {
          // completely out of stock — never dispensable, never chargeable
          quantityDispensed = 0;
          outOfStock = true;
          unavailableDrugs.push(drugNameForRecord);

        } else {
          // never trust the client blindly — re-clamp server side to
          // whatever's actually on the shelf and whatever was requested
          const wanted = Math.max(quantityRequested, quantitySubmitted, 0);
          quantityDispensed = Math.min(wanted, available);

          if (quantityDispensed > 0) {
            inventoryDrug.quantityInStock -= quantityDispensed;
            await inventoryDrug.save();
          }

          if (wanted > quantityDispensed) {
            outOfStock = true; // shortfall — goes on the print slip
            shortfallDrugs.push(`${drugNameForRecord} (${quantityDispensed} of ${wanted})`);
          }
        }

        totalCost = quantityDispensed * unitCost;

      } else {
        // not in inventory at all (includes "ambiguous" fuzzy matches) —
        // we have no reliable price or stock info, so this can never be
        // charged or dispensed through the system. Always unavailable.
        notInInventory    = true;
        outOfStock         = true;
        quantityDispensed  = 0;
        unitCost           = 0;
        totalCost          = 0;
        unavailableDrugs.push(
          matchType === "ambiguous"
            ? `${drugNameForRecord} (multiple close matches — please verify manually)`
            : drugNameForRecord
        );
      }

      dispensedDrugs.push({
        drugName:          drugNameForRecord,
        quantityRequested: Math.max(quantityRequested, quantitySubmitted, 0),
        quantity:          quantityDispensed,
        unitCost,
        totalCost,
        outOfStock,
        notInInventory,
        dispensedBy: req.session.userId,
        dispensedAt: new Date()
      });

      drugFee += totalCost;
    }

    visit.dispensedDrugs      = dispensedDrugs;
    visit.pharmacyNotes       = sanitizeInput(pharmacyNotes);
    visit.pharmacyCompletedAt = new Date();
    visit.pharmacyCompletedBy = req.session.userId;

    if (!visit.billing) visit.billing = {};
    visit.billing.drugFee = drugFee;

    visit.status = "billing";

    await visit.save();

    const notFullyDispensedCount = dispensedDrugs.filter(d => d.outOfStock).length;

    let message = "Drugs dispensed and visit sent to billing";
    if (notFullyDispensedCount > 0) {
      message += `. ${notFullyDispensedCount} item(s) could not be fully dispensed — a takeaway slip is ready to print.`;
    }
    if (autoCorrected.length > 0) {
      message += ` Auto-corrected spelling: ${autoCorrected.join(", ")}.`;
    }

    req.flash("success", message);

    if (notFullyDispensedCount > 0) {
      return res.redirect(`/pharmacy/print/${visit._id}`);
    }

    return res.redirect("/pharmacy");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/pharmacy");
  }
});

// ── PHARMACY PRINT SLIP — pharmacist, admin ──
app.get("/pharmacy/print/:visitId", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId)
      .populate("patient")
      .populate("doctor");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/pharmacy");
    }

    const missingDrugs = (visit.dispensedDrugs || [])
      .filter(d => d.outOfStock)
      .map(d => {
        const rx = (visit.prescriptions || []).find(
          p => drugNameText(p.drugName).toLowerCase() === drugNameText(d.drugName).toLowerCase()
        );
        const given  = d.quantity || 0;
        const needed = d.quantityRequested || given;

        return {
          drugName:  drugNameText(d.drugName),
          dosage:    rx ? rx.dosage    : "",
          frequency: rx ? rx.frequency : "",
          duration:  rx ? rx.duration  : "",
          route:     rx ? rx.route     : "",
          notInInventory:  !!d.notInInventory,
          quantityGiven:   given,
          quantityNeeded:  needed,
          quantityShort:   Math.max(needed - given, 0)
        };
      });

    res.render("pharmacyPrint", {
      visit,
      patient:      visit.patient,
      doctor:       visit.doctor,
      missingDrugs,
      printedAt:    new Date(),
      printedBy:    req.session.name
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Could not load the print slip");
    res.redirect("/pharmacy");
  }
});


// ── DRUG INVENTORY — pharmacy, admin ──
app.get("/inventory", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const { search, category, stockStatus } = req.query;

    const now  = new Date();
    const soon = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days out

    let query = {};

    if (search && search.trim()) {
      const re = new RegExp(search.trim(), "i");
      query.$or = [
        { name:         re },
        { genericName:  re },
        { batchNumber:  re },
        { serialNumber: re }
      ];
    }

    if (category) {
      query.category = category;
    }

    if (stockStatus === "low") {
      query.$expr = {
        $and: [
          { $gt:  ["$quantityInStock", 0] },
          { $lte: ["$quantityInStock", "$reorderLevel"] }
        ]
      };
    } else if (stockStatus === "out") {
      query.quantityInStock = { $lte: 0 };
    } else if (stockStatus === "expiring") {
      query.expiryDate = { $gte: now, $lte: soon };
    } else if (stockStatus === "expired") {
      query.expiryDate = { $lt: now };
    }

    const drugs = await Drug.find(query).sort({ name: 1 });

    // stats computed off the FULL collection, not the filtered view
    const allDrugs = await Drug.find();

    const totalDrugs = allDrugs.length;

    const lowStock = allDrugs.filter(
      d => d.quantityInStock > 0 && d.quantityInStock <= d.reorderLevel
    ).length;

    const outOfStock = allDrugs.filter(d => d.quantityInStock <= 0).length;

    const expiringSoon = allDrugs.filter(
      d => d.expiryDate && d.expiryDate >= now && d.expiryDate <= soon
    ).length;

    const categoriesRaw = await Drug.distinct("category");
    const categories = categoriesRaw.filter(Boolean).sort();

    res.render("inventory", {
      drugs,
      totalDrugs,
      lowStock,
      outOfStock,
      expiringSoon,
      categories,
      search:      search      || "",
      category:    category    || "",
      stockStatus: stockStatus || "",
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading inventory");
    res.redirect("/dashboard");
  }
});

// ── ADD NEW DRUG ──
app.post("/inventory/add", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const name         = sanitizeInput(req.body.name);
    const genericName  = sanitizeInput(req.body.genericName);
    const category     = sanitizeInput(req.body.category);
    const form         = sanitizeInput(req.body.form);
    const strength     = sanitizeInput(req.body.strength);
    const unit         = sanitizeInput(req.body.unit);
    const manufacturer = sanitizeInput(req.body.manufacturer);
    const batchNumber  = sanitizeInput(req.body.batchNumber);
    const serialNumber = sanitizeInput(req.body.serialNumber);

    const quantityInStock = parseFloat(req.body.quantityInStock) || 0;
    const reorderLevel    = parseFloat(req.body.reorderLevel)    || 10;
    const costPrice        = parseFloat(req.body.costPrice)       || 0;
    const sellingPrice      = parseFloat(req.body.sellingPrice)     || 0;
    const expiryDate       = req.body.expiryDate ? new Date(req.body.expiryDate) : null;

    if (!name || !category) {
      req.flash("error", "Drug name and category are required");
      return res.redirect("/inventory");
    }

    const newDrug = new Drug({
      name,
      genericName,
      category,
      form,
      strength,
      unit,
      manufacturer,
      batchNumber,
      serialNumber,
      quantityInStock,
      reorderLevel,
      costPrice,
      sellingPrice,
      expiryDate,
      addedBy:         req.session.userId,
      lastRestockedAt: new Date(),
      priceHistory: [{
        batchNumber,
        quantityAdded: quantityInStock,
        costPrice,
        sellingPrice,
        expiryDate,
        note:      "Initial stock",
        changedBy: req.session.userId
      }]
    });

    await newDrug.save();

    req.flash("success", `${name} added to inventory`);
    res.redirect("/inventory");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong adding the drug");
    res.redirect("/inventory");
  }
});

// ── RESTOCK (new batch — quantity + price can change here) ──
app.post("/inventory/:id/restock", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const drug = await Drug.findById(req.params.id);

    if (!drug) {
      req.flash("error", "Drug not found");
      return res.redirect("/inventory");
    }

    const quantityAdded = parseFloat(req.body.quantityAdded) || 0;
    const costPrice      = req.body.costPrice    !== "" ? parseFloat(req.body.costPrice)    : NaN;
    const sellingPrice   = req.body.sellingPrice !== "" ? parseFloat(req.body.sellingPrice) : NaN;
    const batchNumber   = sanitizeInput(req.body.batchNumber);
    const expiryDate    = req.body.expiryDate ? new Date(req.body.expiryDate) : drug.expiryDate;
    const note          = sanitizeInput(req.body.note);

    if (quantityAdded <= 0) {
      req.flash("error", "Quantity added must be greater than zero");
      return res.redirect("/inventory");
    }

    drug.quantityInStock += quantityAdded;

    if (!isNaN(costPrice))    drug.costPrice    = costPrice;
    if (!isNaN(sellingPrice)) drug.sellingPrice = sellingPrice;
    if (batchNumber)          drug.batchNumber  = batchNumber;
    if (expiryDate)           drug.expiryDate   = expiryDate;

    drug.lastRestockedAt = new Date();

    drug.priceHistory.push({
      batchNumber:  batchNumber || drug.batchNumber,
      quantityAdded,
      costPrice:    drug.costPrice,
      sellingPrice: drug.sellingPrice,
      expiryDate:   drug.expiryDate,
      note,
      changedBy: req.session.userId
    });

    await drug.save();

    req.flash("success", `${drug.name} restocked successfully`);
    res.redirect("/inventory");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong restocking this drug");
    res.redirect("/inventory");
  }
});

// ── EDIT DRUG DETAILS (descriptive fields only — price/stock changes go through Restock) ──
app.post("/inventory/:id/edit", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const name         = sanitizeInput(req.body.name);
    const genericName  = sanitizeInput(req.body.genericName);
    const category     = sanitizeInput(req.body.category);
    const form         = sanitizeInput(req.body.form);
    const strength     = sanitizeInput(req.body.strength);
    const unit         = sanitizeInput(req.body.unit);
    const manufacturer = sanitizeInput(req.body.manufacturer);
    const serialNumber = sanitizeInput(req.body.serialNumber);
    const reorderLevel = parseFloat(req.body.reorderLevel) || 10;

    if (!name || !category) {
      req.flash("error", "Drug name and category are required");
      return res.redirect("/inventory");
    }

    await Drug.findByIdAndUpdate(req.params.id, {
      name, genericName, category, form, strength, unit,
      manufacturer, serialNumber, reorderLevel
    });

    req.flash("success", "Drug details updated");
    res.redirect("/inventory");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong updating this drug");
    res.redirect("/inventory");
  }
});

// ── DISCONTINUE / REACTIVATE DRUG (soft toggle — keeps history intact) ──
app.post("/inventory/:id/toggle-status", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const drug = await Drug.findById(req.params.id);

    if (!drug) {
      req.flash("error", "Drug not found");
      return res.redirect("/inventory");
    }

    drug.status = drug.status === "active" ? "discontinued" : "active";
    await drug.save();

    req.flash("success", `${drug.name} marked as ${drug.status}`);
    res.redirect("/inventory");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/inventory");
  }
});

// ── DELETE DRUG (removes entirely — dispensed history stores drug names as
//    plain strings on the Visit, not a reference, so past records are unaffected) ──
app.post("/inventory/:id/delete", allow("pharmacist", "admin"), async (req, res) => {
  try {
    const drug = await Drug.findByIdAndDelete(req.params.id);

    if (!drug) {
      req.flash("error", "Drug not found");
      return res.redirect("/inventory");
    }

    req.flash("success", `${drug.name} removed from inventory`);
    res.redirect("/inventory");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong removing this drug");
    res.redirect("/inventory");
  }
});



// ───────────────────────────────────────────────────────────
// BILL BOOK (price list) — cashier, admin
// ───────────────────────────────────────────────────────────
app.get("/billing/pricebook", allow("cashier", "admin"), async (req, res) => {
  try {
    const items = await PriceItem.find().sort({ category: 1, name: 1 });

    res.render("billingPricebook", {
      items,
      name:    req.session.name,
      role:    req.session.role,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading the bill book");
    res.redirect("/dashboard");
  }
});

app.post("/billing/pricebook/add", allow("cashier", "admin"), async (req, res) => {
  try {
    const name     = sanitizeInput(req.body.name);
    const category = sanitizeInput(req.body.category);
    const price    = parseFloat(req.body.price) || 0;

    if (!name || !category) {
      req.flash("error", "Name and category are required");
      return res.redirect("/billing/pricebook");
    }

    const newItem = new PriceItem({
      name,
      category,
      price,
      createdBy: req.session.userId,
      updatedBy: req.session.userId,
      priceHistory: [{
        price,
        note:      "Initial price",
        changedBy: req.session.userId
      }]
    });

    await newItem.save();

    req.flash("success", `${name} added to the bill book`);
    res.redirect("/billing/pricebook");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong adding this item");
    res.redirect("/billing/pricebook");
  }
});

// Price edits ALWAYS go through here so the audit trail (who/when) is captured.
// Name/category edits don't need a price-history entry, so they're handled
// separately below in the same route based on what actually changed.
app.post("/billing/pricebook/:id/edit", allow("cashier", "admin"), async (req, res) => {
  try {
    const item = await PriceItem.findById(req.params.id);

    if (!item) {
      req.flash("error", "Item not found");
      return res.redirect("/billing/pricebook");
    }

    const name     = sanitizeInput(req.body.name);
    const category = sanitizeInput(req.body.category);
    const newPrice = parseFloat(req.body.price);
    const note     = sanitizeInput(req.body.note);

    if (!name || !category) {
      req.flash("error", "Name and category are required");
      return res.redirect("/billing/pricebook");
    }

    const priceChanged = !isNaN(newPrice) && newPrice !== item.price;

    item.name     = name;
    item.category = category;
    item.updatedBy = req.session.userId;

    if (priceChanged) {
      item.price = newPrice;
      item.priceHistory.push({
        price:     newPrice,
        note:      note || "Price updated",
        changedBy: req.session.userId
      });
    }

    await item.save();

    req.flash("success", `${item.name} updated`);
    res.redirect("/billing/pricebook");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong updating this item");
    res.redirect("/billing/pricebook");
  }
});

app.post("/billing/pricebook/:id/toggle", allow("cashier", "admin"), async (req, res) => {
  try {
    const item = await PriceItem.findById(req.params.id);

    if (!item) {
      req.flash("error", "Item not found");
      return res.redirect("/billing/pricebook");
    }

    item.active    = !item.active;
    item.updatedBy = req.session.userId;
    await item.save();

    req.flash("success", `${item.name} marked as ${item.active ? "active" : "inactive"}`);
    res.redirect("/billing/pricebook");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong");
    res.redirect("/billing/pricebook");
  }
});

// ───────────────────────────────────────────────────────────
// BILLING QUEUE — cashier, admin
// ───────────────────────────────────────────────────────────
//
// A visit lands here once pharmacy sets status:"billing". The FIRST time
// a given visit is opened in this queue, we auto-seed its charge lines
// (Consultation + Drug fee if any) from the Bill Book / pharmacy data,
// then save that onto the visit so further edits persist. We deliberately
// do NOT try to auto-guess Lab Test / Admission charges — tests are a free
// text field, not a controlled list, so the cashier adds those manually
// from the Bill Book dropdown to avoid charging the wrong thing.
app.get("/billing/queue", allow("cashier", "admin"), async (req, res) => {
  try {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const pendingVisits = await Visit.find({ status: "billing" })
      .populate("patient")
      .populate("doctor")
      .sort({ createdAt: 1 });

    const paidToday = await Visit.find({
      status: "completed",
      "billing.paidAt": { $gte: startOfDay }
    })
      .populate("patient")
      .populate("doctor")
      .sort({ "billing.paidAt": -1 });

    // Auto-seed charges for any visit that hasn't been opened here yet
    const consultationItem = await PriceItem.findOne({ category: "Consultation", active: true }).sort({ createdAt: 1 });

    for (const visit of pendingVisits) {
      if (!visit.billing) visit.billing = {};

      if (!visit.billing.charges || visit.billing.charges.length === 0) {
        const seededCharges = [];

        seededCharges.push({
          label:    consultationItem ? consultationItem.name : "Consultation (set price in Bill Book)",
          category: "Consultation",
          amount:   consultationItem ? consultationItem.price : 0,
          source:   "pricebook",
          addedBy:  req.session.userId,
          addedAt:  new Date()
        });

        if (visit.billing.drugFee && visit.billing.drugFee > 0) {
          seededCharges.push({
            label:    "Drugs (Pharmacy)",
            category: "Drug",
            amount:   visit.billing.drugFee,
            source:   "pharmacy",
            addedBy:  req.session.userId,
            addedAt:  new Date()
          });
        }

        visit.billing.charges = seededCharges;
        visit.billing.totalAmount = seededCharges.reduce((sum, c) => sum + c.amount, 0);
        await visit.save();
      }
    }

    const priceItems = await PriceItem.find({ active: true }).sort({ category: 1, name: 1 });

    res.render("billingQueue", {
      pendingVisits,
      paidToday,
      priceItems,
      name:    req.session.name,
      role:    req.session.role,
      csrfToken: res.locals.csrfToken,
      success: req.flash("success"),
      error:   req.flash("error")
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Error loading billing queue");
    res.redirect("/dashboard");
  }
});

function recomputeTotal(visit) {
  visit.billing.totalAmount = (visit.billing.charges || []).reduce((sum, c) => sum + (c.amount || 0), 0);
}

// Add a charge line — either picked from the Bill Book (priceItemId) or a
// fully custom one-off charge (label + amount typed directly).
app.post("/billing/:visitId/charges/add", allow("cashier", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId);

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/billing/queue");
    }

    const priceItemId = req.body.priceItemId;
    let label, category, amount;

    if (priceItemId) {
      const item = await PriceItem.findById(priceItemId);
      if (!item) {
        req.flash("error", "Selected bill book item not found");
        return res.redirect("/billing/queue");
      }
      label    = item.name;
      category = item.category;
      amount   = item.price;
    } else {
      label    = sanitizeInput(req.body.label);
      category = "Other";
      amount   = parseFloat(req.body.amount) || 0;

      if (!label) {
        req.flash("error", "Please enter a charge description");
        return res.redirect("/billing/queue");
      }
    }

    if (!visit.billing) visit.billing = { charges: [] };
    if (!visit.billing.charges) visit.billing.charges = [];

    visit.billing.charges.push({
      label,
      category,
      amount,
      source:  priceItemId ? "pricebook" : "manual",
      addedBy: req.session.userId,
      addedAt: new Date()
    });

    recomputeTotal(visit);
    await visit.save();

    req.flash("success", `${label} added to the bill`);
    res.redirect("/billing/queue");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong adding this charge");
    res.redirect("/billing/queue");
  }
});

// Edit the amount on an existing charge line — records who edited it.
app.post("/billing/:visitId/charges/:chargeId/edit", allow("cashier", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId);

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/billing/queue");
    }

    const charge = visit.billing.charges.id(req.params.chargeId);

    if (!charge) {
      req.flash("error", "Charge not found");
      return res.redirect("/billing/queue");
    }

    const newAmount = parseFloat(req.body.amount);
    if (isNaN(newAmount) || newAmount < 0) {
      req.flash("error", "Please enter a valid amount");
      return res.redirect("/billing/queue");
    }

    charge.amount   = newAmount;
    charge.editedBy = req.session.userId;
    charge.editedAt = new Date();

    recomputeTotal(visit);
    await visit.save();

    req.flash("success", `${charge.label} updated`);
    res.redirect("/billing/queue");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong updating this charge");
    res.redirect("/billing/queue");
  }
});

app.post("/billing/:visitId/charges/:chargeId/remove", allow("cashier", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId);

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/billing/queue");
    }

    visit.billing.charges = visit.billing.charges.filter(
      c => c._id.toString() !== req.params.chargeId
    );

    recomputeTotal(visit);
    await visit.save();

    req.flash("success", "Charge removed");
    res.redirect("/billing/queue");

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong removing this charge");
    res.redirect("/billing/queue");
  }
});

// ───────────────────────────────────────────────────────────
// CONFIRM PAYMENT — cashier, admin
// ───────────────────────────────────────────────────────────
// No payment gateway is involved. The patient has already paid via
// Mobile Money or POS outside the system; the cashier is only confirming
// that money was received and recording how, before printing the receipt.
app.post("/billing/:visitId/pay", allow("cashier", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId);

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/billing/queue");
    }

    const paymentMethod    = sanitizeInput(req.body.paymentMethod);
    const paymentReference = sanitizeInput(req.body.paymentReference);
    const amountReceived   = parseFloat(req.body.amountReceived) || 0;

    if (!paymentMethod) {
      req.flash("error", "Please select how payment was received");
      return res.redirect("/billing/queue");
    }

    recomputeTotal(visit);

    const receiptNumber = "RCT" + Date.now().toString().slice(-8);

    visit.billing.paymentMethod    = paymentMethod;
    visit.billing.paymentReference = paymentReference;
    visit.billing.amountReceived   = amountReceived;
    visit.billing.receiptNumber    = receiptNumber;
    visit.billing.paidAt           = new Date();
    visit.billing.paidBy           = req.session.userId;

    visit.status = "completed";

    await visit.save();

    req.flash("success", `Payment confirmed. Receipt ${receiptNumber} ready to print.`);
    return res.redirect(`/billing/receipt/${visit._id}`);

  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong confirming payment");
    res.redirect("/billing/queue");
  }
});

// ───────────────────────────────────────────────────────────
// PRINTABLE RECEIPT — cashier, admin
// ───────────────────────────────────────────────────────────
app.get("/billing/receipt/:visitId", allow("cashier", "admin"), async (req, res) => {
  try {
    const visit = await Visit.findById(req.params.visitId)
      .populate("patient")
      .populate("doctor")
      .populate("billing.paidBy", "name");

    if (!visit) {
      req.flash("error", "Visit not found");
      return res.redirect("/billing/queue");
    }

    res.render("billingReceipt", {
      visit,
      patient:   visit.patient,
      doctor:    visit.doctor,
      printedAt: new Date(),
      printedBy: req.session.name
    });

  } catch (err) {
    console.error(err);
    req.flash("error", "Could not load the receipt");
    res.redirect("/billing/queue");
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