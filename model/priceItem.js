const mongoose = require("mongoose");

const priceHistorySchema = new mongoose.Schema({
  price:     { type: Number, required: true },
  note:      { type: String, default: "" },
  changedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  changedAt: { type: Date, default: Date.now }
}, { _id: false });

const priceItemSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    required: true,
    enum: ["Consultation", "Lab Test", "Admission", "Procedure", "Other"]
  },
  price: {
    type: Number,
    required: true,
    default: 0
  },
  active: {
    type: Boolean,
    default: true
  },
  priceHistory: {
    type: [priceHistorySchema],
    default: []
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

module.exports = mongoose.model("PriceItem", priceItemSchema);
