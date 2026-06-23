const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  password: {
    type: String,
    required: true
  },

  phone: {
    type: String,
    trim: true
  },

  dob: {
    type: Date
  },

  gender: {
    type: String,
    enum: ["male", "female", "other"]
  },

  address: {
    type: String,
    trim: true
  },

  emergencyContact: {
    type: String,
    trim: true
  },

  role: {
    type: String,
    required: true,
    enum: ["doctor", "nurse", "admin", "lab"]
  },

  department: {
    type: String,
    trim: true
  },

  staffID: {
    type: String,
    unique: true
  },

onDuty: {
  type: Boolean,
  default: false
},

dutyStartedAt: {
  type: Date
},

dutyEndsAt: {
  type: Date
},
  
  loginAttempts: {
    type: Number,
    default: 0
  },

  lockUntil: {
    type: Date,
    default: null
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  editedAt: {
  type: Date,
  default: null
},
resetPasswordToken:   { type: String },
resetPasswordExpires: { type: Date },

editedBy: {
  type: mongoose.Schema.Types.ObjectId,
  ref: "User",
  default: null
}

});



module.exports = mongoose.model("User", userSchema);