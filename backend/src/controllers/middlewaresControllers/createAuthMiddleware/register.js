const bcrypt = require('bcryptjs');
const Joi = require('joi');
const mongoose = require('mongoose');
const { generate: uniqueId } = require('shortid');
const { loadSettings } = require('@/middlewares/settings');

const checkAndCorrectURL = require('./checkAndCorrectURL');
// const sendMail = require('./sendMail');
const nodemailer = require("nodemailer");
// const sendMail = require('./sendMail');
const register = async (req, res, { userModel }) => {



  const UserPassword = mongoose.model(userModel + 'Password');
  const User = mongoose.model(userModel);
  const { name, email, password } = req.body;

  // validate
  const objectSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string()
      .email({ tlds: { allow: true } })
      .required(),
    password: Joi.string().required(),
  });

  const { error, value } = objectSchema.validate({ name, email, password });
  if (error) {
    return res.status(409).json({
      success: false,
      result: null,
      error: error,
      message: 'Invalid/Missing credentials.',
      errorMessage: error.message,
    });
  }

  const existingUser = await User.findOne({ email: email, removed: false });
  if (existingUser) {
    return res.status(409).json({
      success: false,
      result: null,
      message: 'An account with this email has already been registered.',
    });
  }

  const salt = uniqueId();
  const hashedPassword = bcrypt.hashSync(salt + password);
  const emailToken = uniqueId();

  const savedUser = await User.create({ email, name });

  const registrationDone = await UserPassword.create({
    user: savedUser._id,
    password: hashedPassword,
    salt: salt,
    emailToken,
  });

  if (!registrationDone) {
    await User.deleteOne({ _id: savedUser._id }).exec();

    return res.status(403).json({
      success: false,
      result: null,
      message: "document couldn't save correctly",
    });
  }

  try {
    const transporter = nodemailer.createTransport({

      host: process.env.HOST,
      service: process.env.SERVICE,
      port: 587,
      secure: true,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
    });

    const message = `http://localhost:3000/api/verify/${savedUser._id}/${emailToken}`
    await transporter.sendMail({
      from: process.env.USER,
      to: email,
      subject: 'please verify your account',
      text: "Verification",
      html: `<body style="font-family: Helvetica, Arial, sans-serif; margin: 0px; padding: 0px; background-color: #ffffff;">
  <table role="presentation"
    style="width: 100%; border-collapse: collapse; border: 0px; border-spacing: 0px; font-family: Arial, Helvetica, sans-serif; background-color: rgb(239, 239, 239);">
    <tbody>
      <tr>
        <td align="center" style="padding: 1rem 2rem; vertical-align: top; width: 100%;">
          <table role="presentation" style="max-width: 600px; border-collapse: collapse; border: 0px; border-spacing: 0px; text-align: left;">
            <tbody>
              <tr>
                <td style="padding: 40px 0px 0px;">
                  <div style="text-align: left;">
                    <div style="padding-bottom: 20px;"><img src="https://i.ibb.co/Qbnj4mz/logo.png" alt="Company" style="width: 56px;"></div>
                  </div>
                  <div style="padding: 20px; background-color: rgb(255, 255, 255);">
                    <div style="color: rgb(0, 0, 0); text-align: left;">
                      <h1 style="margin: 1rem 0">Welcome...</h1>
                      <h2 style="padding-bottom: 16px">Follow this link to verify your email address.</h2>
                      <p style="padding-bottom: 16px"><a href=${message} target="_blank"
                          style="padding: 12px 24px; border-radius: 4px; color: #FFF; background: #2B52F5;display: inline-block;margin: 0.5rem 0;">Confirm
                          now</a></p>
                      <p style="padding-bottom: 16px">If you didn’t ask to verify this address, you can ignore this email.</p>
                      <p style="padding-bottom: 16px">Thanks,<br>THE ERP SOFTWARE TEAM</p>
                    </div>
                  </div>
                  <div style="padding-top: 20px; color: rgb(153, 153, 153); text-align: center;">
                    <p style="padding-bottom: 16px">Made with ♥ in Sivabalan-©</p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </td>
      </tr>
    </tbody>
  </table>
    </body>`
    });
    console.log("email sent sucessfully");

  } catch (error) {
    console.log("email not sent");
    console.log(error);
  }

  // await sendMail(email, "Verify Email", message);


  return res.status(200).json({
    success: true,
    result: {
      _id: savedUser._id,
      name: savedUser.name,
      email: savedUser.email,
      message: 'Account registered successfully. Please verify your email.',
    },
  });

};

module.exports = register;
