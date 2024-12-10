import bcrypt from "bcryptjs"
import User from "../models/User.js"
import jwt from "jsonwebtoken"

export const register = async (req, res, next) => {
  const {name, email, password} = req.body;
  if (!name || !email || !password) {
    return res.status(400).send("Missing required fields");
  }

  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({message:"Email already exists"});
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  try{
    const newUser = new User({
      name: name,
      email: email,
      password: hash
    })
    await newUser.save();    
    const accessToken = jwt.sign({ id: newUser._id, isAdmin: newUser.isAdmin }, process.env.JWT_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
    console.log(req.body);
    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day expiration
      sameSite: 'strict' 
    };

    const { password, isAdmin, ...otherDetails } = newUser._doc;
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .json({ user: { ...otherDetails }, isAdmin });

    

  }catch(err){
    console.error("Error during registration:", err);
    next(err);
  }
}

// export const register = async (req, res, next) => {
//   const { name,email } = req.body;
//   const password = req.body.password;
//   if (!name || !email || !password) {
//     return res.status(400).json({ message: "All fields are required" });
//   }
  


//   console.log("Request Body:", req.body);

//   try {
//     // Check if user exists
//     const userExists = await User.findOne({ email });
//     console.log("User Exists:", userExists);
//     if (userExists) return res.status(400).json({ message: "Email already exists" });

//     // Hash the password
//     const salt = bcrypt.genSaltSync(10);
//     const hash = bcrypt.hashSync(password, salt);

//     // Save the user
//     const newUser = new User({ name, email, password: hash });
//     const savedUser = await newUser.save();
//     console.log("Saved User:", savedUser);

//     // Generate JWT token
//     const accessToken = jwt.sign(
//       { id: savedUser._id, isAdmin: savedUser.isAdmin },
//       process.env.JWT_SECRET,
//       { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
//     );
//     console.log("Access Token:", accessToken);

//     const options = {
//       httpOnly: true,
//       secure: true,
//       maxAge: 24 * 60 * 60 * 1000,
//       sameSite: 'strict',
//     };

//     const { password, isAdmin, ...otherDetails } = savedUser._doc;
//     return res
//       .status(200)
//       .cookie("accessToken", accessToken, options)
//       .json({ user: { ...otherDetails }, isAdmin });
//   } catch (err) {
//     console.error("Error during registration:", err);
//     next(err);
//   }
// };


export const login = async(req, res, next)=>{
  try{
    const user = await User.findOne({email: req.body.email})

    if (!user || !await bcrypt.compare(req.body.password, user.password)) {
      return res.status(400).json({message:"Wrong email or password"});
    }
    const accessToken = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
    console.log(accessToken)
    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day expiration
      sameSite: 'strict' 
    };

    const { password, isAdmin, ...otherDetails } = user._doc;
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .json({ user: { ...otherDetails }, isAdmin });
  }catch(err){
    next(err)
  }
}

export const logout = async (req, res, next) => {
  try{
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: true,
    });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    next(err);
  }
};