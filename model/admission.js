const mongoose = require("mongoose");

const admissionSchema = new mongoose.Schema({

  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Patient",
    required: true
  },

  admittedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  admittedAt: {
    type: Date,
    default: Date.now
  },

  ward: {
    type: String,
    trim: true
  },

  bed: {
    type: String,
    trim: true
  },

  // clinical status
  status: {
    type: String,
    enum: ["stable", "critical", "observation", "chronic", "deceased", "discharged"],
    default: "observation"
  },

  // reason for admission
  admissionReason: {
    type: String,
    trim: true
  },

  // ward rounds — doctor visits during the stay
  wardRounds: [
    {
      notes:    { type: String },
      addedBy:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      addedAt:  { type: Date, default: Date.now },
      vitals: {
        temperature:     Number,
        bloodPressure:   String,
        heartRate:       Number,
        respiratoryRate: Number,
        weight:          Number
      }
    }
  ],

  // medications — IV, saline, drugs etc
medications: [
  {
    name: String,
    dosage: String,
    frequency: String,

    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },

    addedAt: {
      type: Date,
      default: Date.now
    },

    // NEW
    active: {
      type: Boolean,
      default: true
    },

    removedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },

    removedAt: Date
  }
],

  // lab requests raised during admission
  labRequests: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Visit"
    }
  ],

  // discharge info
  dischargedAt:    { type: Date },
  dischargeNotes:  { type: String },
  dischargedBy:    { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  isActive: {
    type: Boolean,
    default: true
  },

  // was this an emergency admission (bypassed queue)
  isEmergency: {
    type: Boolean,
    default: false
  }

});

module.exports = mongoose.model("Admission", admissionSchema);