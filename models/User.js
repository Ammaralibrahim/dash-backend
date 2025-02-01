// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true, // Her e-posta adresinin benzersiz olmasını sağlıyoruz.
  },
  password: {
    type: String,
    required: true,
  },
}, { timestamps: true }); // Kullanıcı kaydedildiği zaman otomatik olarak 'createdAt' ve 'updatedAt' alanları eklenir.

const User = mongoose.model('User', userSchema);

module.exports = User;
