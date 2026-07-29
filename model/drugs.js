const mongoose = require("mongoose");

// Every time stock is topped up (a "restock"), we snapshot what was paid,
// what it was sold for, the batch it came in on, and its expiry — so if
// a price changes between batches, the old price isn't just overwritten
// and lost. This is what lets you answer "when did this go up?" later.
const priceHistorySchema = new mongoose.Schema({
  batchNumber:   String,
  quantityAdded: Number,
  costPrice:     Number,
  sellingPrice:  Number,
  expiryDate:    Date,
  note:          String,
  changedBy:     { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  changedAt:     { type: Date, default: Date.now }
}, { _id: false });

const drugSchema = new mongoose.Schema({

  // ── IDENTITY ──
  name:         { type: String, required: true },   // brand/trade name, e.g. "Panadol"
  genericName:  String,                              // e.g. "Paracetamol"
  category:     String,                               // e.g. "Analgesic", "Antibiotic"
  form: {
    type: String,
    enum: ["Tablet", "Capsule", "Syrup", "Injection", "Cream", "Ointment", "Drops", "Inhaler", "Suppository", "Other"],
    default: "Tablet"
  },
  strength:     String,   // e.g. "500mg"
  unit:         { type: String, default: "unit" },  // e.g. "tablet", "bottle", "vial", "tube"
  manufacturer: String,

  // ── IDENTIFIERS (current batch) ──
  batchNumber:  String,   // most recent lot/batch number
  serialNumber: String,   // barcode / internal serial, optional

  // ── STOCK ──
  quantityInStock: { type: Number, default: 0 },
  reorderLevel:    { type: Number, default: 10 },   // triggers "Low Stock" badge at/below this

  // ── CURRENT PRICING (mirrors the latest priceHistory entry) ──
  costPrice:    { type: Number, default: 0 },  // what the pharmacy paid per unit
  sellingPrice: { type: Number, default: 0 },  // what the patient is charged per unit

  // ── EXPIRY (current batch) ──
  expiryDate: Date,

  status: {
    type: String,
    enum: ["active", "discontinued"],
    default: "active"
  },

  // ── FULL BATCH/PRICE HISTORY ──
  priceHistory: [priceHistorySchema],

  addedBy:         { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  lastRestockedAt: Date,
  createdAt:       { type: Date, default: Date.now }

});

module.exports = mongoose.model("Drug", drugSchema);