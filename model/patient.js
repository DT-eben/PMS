const mongoose = require("mongoose");

const patientSchema = new mongoose.Schema({

  // 🆔 BASIC INFO
  name: {
    type: String,
    required: true,
    trim: true
  },

  patientID: {
    type: String,
    unique: true
  },

  DOB: {
    type: Date,
    required: true
  },

  gender: {
    type: String,
    required: true
  },

  // 📞 CONTACT INFO
  number: {
    type: String,
    required: true
  },

  email: String,

  address: {
    type: String,
    required: true
  },

  // 🚨 EMERGENCY
  emergencyContact: {
    type: String,
    required: true
  },

  nextOfKin: String,

  // 👤 PERSONAL INFO
  occupation: String,

  maritalStatus: String,

  // 💳 INSURANCE
  insurance: String,

  insuranceNumber: String,

  // 🩸 OPTIONAL BASIC MEDICAL INFO
  bloodType: String,
  allergies: String,

  createdBy: {
  type: mongoose.Schema.Types.ObjectId,
  ref: "User",
  required: true
},

  // 📅 SYSTEM INFO
  createdAt: {
    type: Date,
    default: Date.now
  }

});

module.exports = mongoose.model("Patient", patientSchema);