import UserModel from "../model/User.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import ENV from "../config.js";
import otpGenerator from "otp-generator";

// middleware for verify user
export async function verifyUser(req, res, next) {
  try {
    const { username } = req.method == "GET" ? req.query : req.body;

    //check the user existance
    let exist = await UserModel.findOne({ username });
    if (!exist) return res.status(404).send({ error: "Can;t find user!" });
    next();
  } catch (error) {
    return res.status(400).send({ error: "Authentication Error" });
  }
}

/** POST: http://localhost:8080/api/register
    @param : {
        "username" : "example123",
        "password" : "example123",
        "email" : "test@gmail.com",
        "firstName" : "bill",
        "lastName" : "william",
        "mobile" : 8088983809,
        "address" : "Apt. 556, kulas Light, Gwenborough",
        "profile" : ""
    }
 */

export async function register(req, res) {
  try {
    const { username, password, profile, email } = req.body;
    const existUsername = UserModel.findOne({ username }).exec();
    const existEmail = UserModel.findOne({ email }).exec();
    const [usernameExists, emailExists] = await Promise.all([
      existUsername,
      existEmail,
    ]);

    if (usernameExists) {
      return res.status(400).send({ error: "Please use a unique username" });
    }

    if (emailExists) {
      return res.status(400).send({ error: "Please use a unique email" });
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = new UserModel({
        username,
        password: hashedPassword,
        profile: profile || "",
        email,
      });

      const result = await user.save();

      res.status(201).send({ msg: "User Register Successful" });
    }
  } catch (error) {
    res.status(500).send({ error: error.message || "Internal Server Error" });
  }
}

export async function login(req, res) {
  //   res.json("login route");

  const { username, password } = req.body;

  try {
    UserModel.findOne({ username })
      .then((user) => {
        bcrypt.compare(password, user.password).then((passwordCheck) => {
          if (!passwordCheck)
            return res.status(400).send({ error: "Dont have Password" });

          // create jwt token
          const token = jwt.sign(
            {
              userId: user._id,
              username: user.username,
            },
            ENV.JWT_SECRET,
            { expiresIn: "24h" }
          );

          return res.status(200).send({
            msg: "Login Successful...!",
            username: user.username,
            token,
          });
        });
      })
      .catch((error) => {
        return res.status(404).send({ error: "Username not Found" });
      });
  } catch (error) {
    return res.status(500).send({ error });
  }
}

export async function getUser(req, res) {
  try {
    const { username } = req.params;

    if (!username) {
      return res.status(400).send({ error: "Invalid Username" });
    }

    const user = await UserModel.findOne({ username });

    if (!user) {
      return res.status(404).send({ error: "User Not Found" });
    }

    // Omit password from user object
    const { password, ...userData } = user.toObject();

    return res.status(200).send(userData);
  } catch (error) {
    console.error("Error in getUser:", error);
    return res.status(500).send({ error: "Internal Server Error" });
  }
}

export async function updateUser(req, res) {
  try {
    // const id = req.query.id;
    const { userId } = req.user;

    if (!id) {
      return res.status(400).send({ error: "Invalid or Missing ID" });
    }
    const body = req.body;

    const updateResult = await UserModel.updateOne({ _id: userId }, body);

    if (updateResult.modifiedCount > 0) {
      return res.status(200).send({ msg: "Record Updated Successfully" });
    } else {
      return res
        .status(404)
        .send({ error: "User Not Found or No Changes Made" });
    }
  } catch (error) {
    return res.status(500).send({ error: "Internal Server Error" });
  }
}

export async function generateOTP(req, res) {
  req.app.locals.OTP = await otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  res.status(201).send({ code: req.app.locals.OTP });
}

export async function verifyOTP(req, res) {
  const { code } = req.query;
  if (parseInt(req.app.locals.OTP) === parseInt(code)) {
    req.app.locals.OTP = null;
    req.app.locals.resetSession = true; 
    return res.status(201).send({ msg: "Verify Successfully!" });
  }
  return res.status(400).send({ error: "Invalid OTP" });
}

export async function createResetSession(req, res) {
  if (req.app.locals.resetSession) {
    req.app.locals.resetSession = false;
    return res.status(201).send({ msg: "access granted!" });
  }
  return res.status(440).send({ error: "Session expired!" });
}

export async function resetPassword(req,res){
  try {
      
      if(!req.app.locals.resetSession) return res.status(440).send({error : "Session expired!"});

      const { username, password } = req.body;

      try {
          
          UserModel.findOne({ username})
              .then(user => {
                  bcrypt.hash(password, 10)
                      .then(hashedPassword => {
                        UserModel.updateOne({ username: user.username }, { password: hashedPassword })
                        .exec()
                        .then((data) => {
                            req.app.locals.resetSession = false; // reset session
                            return res.status(201).send({ msg: "Record Updated...!" });
                        })
                        .catch((err) => {
                            throw err; // Handle the error appropriately, log or send an error response
                        });
                    
                      })
                      .catch( e => {
                          return res.status(500).send({
                              error : "Enable to hashed password"
                          })
                      })
              })
              .catch(error => {
                  return res.status(404).send({ error : "Username not Found"});
              })

      } catch (error) {
          return res.status(500).send({ error })
      }

  } catch (error) {
      return res.status(401).send({ error })
  }
}