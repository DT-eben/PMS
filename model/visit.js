const mongoose = require("mongoose");

const visitSchema = new mongoose.Schema({
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Patient",
    required: true
  },

  // 🔥 VITALS (from nurse)
  vitals: {
    temperature: Number,
    bloodPressure: String,
    heartRate: Number,
    respiratoryRate: Number,
    weight: Number,
    height: Number
  },

  // 👨‍⚕️ DOCTOR INPUT
  complaint: String,
  observation: String,
  diagnosis: String,
  prescription: String,
  notes: String,
  tests: String, // lab requests

  // 🧪 LAB RESULT (PDF path)
  labResult: String,

  // 🔁 STATUS FLOW
  status: {
    type: String,
    default: "waiting"
    // possible values:
    // "waiting"
    // "in-progress"
    // "lab"
    // "completed"
    // (future: "admitted")
  },

  // 👩‍⚕️ NURSE WHO RECORDED VITALS
  nurse: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  doctor: {
 type: mongoose.Schema.Types.ObjectId,
  ref: "User"
   },

   labResults: String,
   labCompletedAt: Date,
  labCompletedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  
// LAB TYPE
labType: {
  type: String,
  enum: ["internal", "external"],
  default: "internal"
},

// EXTERNAL LAB
externalLabStatus: {
  type: String,
  enum: ["pending", "completed"],
},

externalLabName: String,

externalLabSentAt: Date,

externalLabCompletedAt: Date,

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Visit", visitSchema);