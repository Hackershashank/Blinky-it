import sendEmail from '../config/sendEmail.js';
import UserModel from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';
import generatedAccessToken from '../utils/generatedAccessToken.js';
import generatedRefreshToken from '../utils/generatedRefreshToken.js';
import uploadImageCloudinary from '../utils/uploadImageCloudinary.js';
import auth from '../middleware/auth.js';
import bcrypt from 'bcryptjs';

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
        if(!email || !password){
            return res.status(400).json({
                message:"Provide email and password",
                error:true,
                success:false
            })
        }
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
                message:"Contact to admin",
                error:true,
                success:false
            })
        }
        const checkPassword=await bcryptjs.compare(password,user.password)
        if(!checkPassword){
            return res.status(404).json({
                message:"check your password",
                error:true,
                success:false
            })
        }
        //access token & refresh token
        const accessToken=await generatedAccessToken(user._id);
        const refreshToken=await generatedRefreshToken(user._id);

        const cookiesOption={
            httpOnly:true,
            secure:true,
            sameSite:"None"
        }
        res.cookie('accessToken',accessToken,cookiesOption)
        res.cookie('refreshToken',refreshToken,cookiesOption)

        return res.json({
            message:"Logged in successfully",
            error:false,
            success:true,
            date:{
                accessToken,
                refreshToken
            }
        })

    } catch (error) {
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
}
//logout controller
export async function logoutController(req,res){
    try {
        const userId=req.userId // middleware
        
        const cookiesOption = {
            httpOnly:true,
            secure:true,
            sameSite:"None"
        }

        res.clearCookie("accessToken",cookiesOption);
        res.clearCookie("refreshToken",cookiesOption);

        const removeRefreshToken=await UserModel.findByIdAndUpdate(userId,{
            refresh_token:""
        })

        return res.json({
            message:"Logged out successfully",
            error:false,
            success:true
        })
    } catch (error) {
        return res.status(500).json({
            message:error,
            error:true,
            success:false
        })
    }
}
//upload User Avatar
export async function uploadAvatar(req,res){
    try {
        const userId=req.userId //auth middleware   
        const image=req.file; //multer middleware
        const upload=await uploadImageCloudinary(image);
        const updateUser=await UserModel.findByIdAndUpdate(userId,{
            avatar:upload.url
        })
        return res.json({
            message:"upload profile",
            data:{
                _id:userId,
                avatar: upload.url
            }
        })
    } catch (error) {
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
}
//update User details
export async function updateUserDetails(req,res){
    try {
        const userId=req.userId //auth middleware
        const {name,email,mobile,password}=req.body;
        let hashPassword="";
        if(password){
            const salt=await bcryptjs.genSalt(10);
            hashPassword=await bcryptjs.hash(password,salt);
        }
        const updateUser=await UserModel.findByIdAndUpdate(userId,{
            ...(name && {name:name}),
            ...(email && {email:email}),
            ...(mobile && {mobile:mobile}),
            ...(password && {password:hashPassword})
        },{new:true})
        return res.json({
            message:"updated user successfully",
            error:false,
            success:true,
            data:updateUser
        })

    } catch (error) {
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false   
        })
    }
}

export default verifyEmailController
