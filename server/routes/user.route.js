import {Router} from 'express';
import verifyEmailController, { registerUserController } from '../controllers/user.controller.js';

const userRouter=Router();
userRouter.post('/register',registerUserController);
userRouter.post('verify-email',verifyEmailController);

export default userRouter;