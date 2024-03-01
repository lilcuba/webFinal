const mongoose = require("mongoose");
require('dotenv').config();

const dbURL = process.env.DB_URL;

mongoose.connect(dbURL)
  .then(() => console.log("Database connected Successfully"))
  .catch((error) => console.log("Database could not be connected:", error));


