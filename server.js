const express = require("express");
const cookieSession = require("cookie-session");
const cors = require("cors");
const router = require("./app/routes/auth.routes");
const connectDB = require("./app/config/config.db");

const dotenv=require("dotenv");
dotenv.config();

const app = express();
const port = process.env.PORT;
const origin= process.env.ORIGIN_PORT;
const cookies_key= process.env.COOKIES_KEY;

//middleware
app.use(express.json());

app.use(
  cors({
    credentials: true,
    origin: [`http://localhost:${origin}`],
  })
);

app.use(express.urlencoded({ extended: true }));

app.use(
  cookieSession({
    name: "-session",
    keys: [cookies_key], 
    httpOnly: true,
    sameSite: 'strict'
  })
);

//use routes
app.use("/api/auth", router);

app.listen(port, async () => {
  console.log(`Server is running on port ${port}`);
  connectDB();
});
