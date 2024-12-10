import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"
import cors from "cors"
import cookieParser from "cookie-parser"
import Razorpay from "razorpay"
import authRoute from "./routes/auth.routes.js"
import userRoute from "./routes/user.routes.js"
import rideRoute from "./routes/ride.routes.js"
import paymentRoute from "./routes/payment.routes.js"
import path from "path"

const app = express()
const PORT = 5000;

dotenv.config()

const connectDB = () => {
  // mongoose.set("strictQuery", true);

  mongoose
    .connect(process.env.MONGO)
    .then(() => console.log("Database connected"))
    .catch((error) => console.log(error));
};

//middlewares
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
}
))

app.use(cookieParser())
app.use(express.json())

app.use("/api/users", userRoute);
app.use("/api/auth", authRoute);
app.use("/api/rides", rideRoute);
app.use("/api", paymentRoute);

app.get("/api/getkey", (req, res)=>{
  res.status(200).json({key: process.env.RAZORPAY_API_KEY});
})
export const instance = new Razorpay ({
  key_id: process.env.RAZORPAY_API_KEY,
  key_secret: process.env.RAZORPAY_SECRET_KEY
})

// ---------------deployment-----------------//
const __dirname1 = path.resolve();
if (process.env.NODE_ENV === 'production') {
  const staticPath = path.join(__dirname1, './client', 'dist');
  console.log('Static Path:', staticPath); 
  app.use(express.static(staticPath));
  app.get('*', (req, res) => {
    const indexPath = path.resolve(__dirname1, './client', 'dist', 'index.html');
    console.log('Index Path:', indexPath); 
    res.sendFile(indexPath);
  });
}

app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  res.status(500).json({ success: false, message: err.message });
});



// app.use((err, req, res, next)=>{
//   const errorStatus = err.status || 500;
//   const errorMessage = err.message || "Something went wrong";
//   return res.status(errorStatus).json({
//     success: false,
//     status: err.status,
//     error: errorMessage
//   })
// })

app.listen(PORT, () => {
  connectDB()
  console.log(`Connected to backend on PORT: ${PORT}`)
})
