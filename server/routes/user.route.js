import {Router} from 'express';
import {verifyEmailController, loginController, registerUserController, logoutController } from '../controllers/user.controller.js';
import auth from '../middleware/auth.js';

const userRouter=Router();
userRouter.post('/register',registerUserController);
userRouter.post('/verify-email',verifyEmailController);
userRouter.post('/login',loginController);
userRouter.post('/logout',auth,logoutController) //auth is middleware i.e it is between the route and funct


export default userRouter;