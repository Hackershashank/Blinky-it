import sendEmail from '../config/sendEmail.js';
import UserModel from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';

export async function registerUserController(req, res) {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "Provide email, name and password",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email });
        if (user) {
            return res.json({
                message: 'Already registered email',
                error: true,
                success: false
            });
        }

        const salt = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(password, salt);

        const newUser = new UserModel({
            name,
            email,
            password: hashPassword
        });

        const save = await newUser.save();

        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save._id}`;
        console.log("🔗 Verification link:", VerifyEmailUrl);

        const verifyEmail = await sendEmail({
            sendTo: email,
            subject: "Verify Email from Blinkyit",
            html: verifyEmailTemplate({
                name,
                url: VerifyEmailUrl
            })
        });

        if (!verifyEmail) {
            return res.status(500).json({
                message: "User created, but verification email failed to send.",
                error: true,
                success: false
            });
        }

        const { pass, ...userInfo } = save._doc;

        return res.json({
            message: "User registered successfully",
            error: false,
            success: true,
            user: userInfo
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}
export async function verifyEmailController(req,res){
    try {
        const {code}=req.body;
        const user=await UserModel.findOne({_id:code})
        if(!user){
            return res.status(400).json({
                message:'Invalid code',
                error:true,
                success:false
            })
        }
        const updateUser=await UserModel.updateOne({_id:code},{
            verify_email:true
        })

        return res.json({
            message:'Email verified',
            error:false,
            success:true
        })

    } catch (error) {
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
}
//login controller
export async function loginController(req,res){
    try {
        const {email,password} = req.body;
        const user=await UserModel.findOne({email});
        if(!user){
            return res.status(400).json({
                message:"User not registered",
                error:true,
                success:false 
            })
        }  
        if(user.status!=="Active"){
            return res.status(400).json({

            })
        }
        

    } catch (error) {
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
}
export default verifyEmailController
