const mongoose = require('mongoose');
const ROLE ={
    ADMIN: 'admin',
    BASIC: 'basic'
}

const UserSchema = new mongoose.Schema({
    username: {
      type: String,
      required: true
    },
    password: {
      type: String,
      required: true
    },
    gender:{
      type: String,
      required: false
    },
    gmail:{
      type: String,
      required: true
    },
    role: {
        type: String,
        default: ROLE.BASIC // Set the default role to 'basic'
    }
  });
  
  const collection = mongoose.model("User", UserSchema);
  
  module.exports = collection;