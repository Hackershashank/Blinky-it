import {Router} from 'express';
import {verifyEmailController, loginController, registerUserController, logoutController, uploadAvatar, updateUserDetails, forgotPasswordController, verifyForgotPasswordOtp, resetPassword } from '../controllers/user.controller.js';
import auth from '../middleware/auth.js';
import upload from '../middleware/multer.js';

const userRouter=Router();
userRouter.post('/register',registerUserController);
userRouter.post('/verify-email',verifyEmailController);
userRouter.post('/login',loginController);
userRouter.post('/logout',auth,logoutController) //auth is middleware i.e it is between the route and funct
userRouter.put('/upload-avatar',auth,upload.single('avatar'),uploadAvatar)
userRouter.put('/update-user',auth,updateUserDetails);
userRouter.put('/forgot-password',forgotPasswordController);
userRouter.put('/verify-forgot-password-otp',verifyForgotPasswordOtp);
userRouter.put('/reset-password',resetPassword);

export default userRouter;