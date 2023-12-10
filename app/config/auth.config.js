const dotenv = require("dotenv");
dotenv.config();

module.exports = {
  port: process.env.port || PORT,
  origin: process.env.ORIGIN_PORT,
  cookies_key: process.env.COOKIES_KEY,
  db: process.env.DATABASE_NAMEconst,
  secret_key: process.env.SECRET_KEY,
  algorithm: process.env.ALGORITHM,
  your_email: process.env.YOUR_EMAIL,
  reset_url: process.env.RESET_URL,
  password: process.env.PASSWORD,
};
