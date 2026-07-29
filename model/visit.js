const mongoose = require("mongoose");

const visitSchema = new mongoose.Schema({

  // ── PATIENT & STAFF ──
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Patient",
    required: true
  },

  nurse: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  doctor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  // ── VITALS (recorded by nurse) ──
  vitals: {
    temperature:     Number,
    bloodPressure:   String,
    heartRate:       Number,
    respiratoryRate: Number,
    weight:          Number,
    height:          Number
  },

  // ── DOCTOR CONSULTATION ──
  complaint:   String,
  observation: String,
  diagnosis:   String,
  notes:       String,

  // ── STRUCTURED PRESCRIPTIONS ──
  // replaces the old single `prescription` String field
  // each drug the doctor prescribes gets its own entry
  prescriptions: [
    {
      drugName:  { type: String },
      dosage:    { type: String },   // e.g. "500mg"
      frequency: { type: String },   // e.g. "Twice daily"
      duration:  { type: String },   // e.g. "5 days"
      route:     { type: String },   // e.g. "Oral", "IV", "Topical"
      notes:     { type: String }    // optional extra instruction
    }
  ],

  // ── LAB ──
  tests:          String,   // lab test(s) requested
  labResult:      String,   // PDF path if uploaded internally
  labResults:     String,   // typed results from lab tech
  labCompletedAt: Date,
  labCompletedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  labType: {
    type: String,
    enum: ["internal", "external"],
    default: "internal"
  },

  externalLabStatus: {
    type: String,
    enum: ["pending", "completed"]
  },

  externalLabName:        String,
  externalLabSentAt:      Date,
  externalLabCompletedAt: Date,

  // ── PHARMACY ──
  // tracks what the pharmacist did with each prescribed drug
  dispensedDrugs: [
    {
      drugName:     { type: String },
      quantity:     { type: Number },
      unitCost:     { type: Number },
      totalCost:    { type: Number },
      outOfStock:   { type: Boolean, default: false },
      dispensedBy:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      dispensedAt:  { type: Date }
    }
  ],

  pharmacyNotes:       String,   // pharmacist can leave a note
  pharmacyCompletedAt: Date,
  pharmacyCompletedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  // ── BILLING ──
  billing: {
    // ── Standard fees (each auto-filled from the Bill Book / pharmacy,
    //    but editable by the cashier — every edit is logged in feeEdits below) ──
    consultationFee: { type: Number, default: 0 },
    labFee:          { type: Number, default: 0 },
    drugFee:         { type: Number, default: 0 },
    admissionFee:    { type: Number, default: 0 },

    // ── One-off / ad-hoc charges not covered by the four fees above
    //    (e.g. "Wound dressing", "Extra procedure") ──
    otherCharges: [
      {
        label:    { type: String, required: true },
        amount:   { type: Number, required: true, default: 0 },
        addedBy:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        addedAt:  { type: Date, default: Date.now },
        editedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        editedAt: { type: Date }
      }
    ],

    // ── Audit trail: every time a fee amount is changed, log who changed
    //    it, when, and what it changed from/to ──
    feeEdits: [
      {
        field:     { type: String },  // "consultationFee" | "labFee" | "drugFee" | "admissionFee"
        oldAmount: { type: Number },
        newAmount: { type: Number },
        editedBy:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        editedAt:  { type: Date, default: Date.now }
      }
    ],

    totalAmount: { type: Number, default: 0 },
    amountPaid:  { type: Number, default: 0 },

    paymentMethod: {
      type: String,
      enum: ["cash", "momo", "card", "insurance", "waived"]
    },

    paymentNote:      String,  // cashier can add a note e.g. "partial payment"
    paymentReference: String, // momo transaction ID / POS slip number
    receiptNumber:    String, // generated when payment is confirmed

    paidAt:      Date,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
  },

  // ── STATUS FLOW ──
  status: {
    type: String,
    default: "waiting",
    enum: [
      "waiting",      // nurse registered patient, waiting for doctor
      "in-progress",  // doctor is currently seeing patient
      "lab",          // sent to lab (internal or external)
      "lab-complete", // lab results back, waiting for doctor review
      "admitted",     // patient admitted to ward
      "pharmacy",     // doctor done, sent to pharmacy
      "billing",      // pharmacy done, sent to cashpoint
      "paid",         // billing complete
      "completed"     // fully done, no billing needed (or already paid)
    ]
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

module.exports = mongoose.model("Visit", visitSchema);