import express from "express";
import cors from 'cors';

import dotenv from 'dotenv';
dotenv.config();

import cookieParser from 'cookie-parser';

import morgan from "morgan";

import helmet from 'helmet';

import connectDB from "./config/connectDB.js";
import userRouter from "./routes/user.route.js";

const app=express();

app.use(cors({
    credentials:true,
    origin:process.env.FRONTEND_URL
}));


app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));
app.use(helmet({
    crossOriginResourcePolicy:false
}));

const PORT=process.env.PORT||8080;

app.get("/",(req,res)=>{
    // server to client data transfer
    res.json({
        message: `Server is running at ${PORT}`
    })
});

app.use('/api/user',userRouter)

connectDB().then(()=>{
    app.listen(PORT,()=>{
        console.log(`Server is running ${PORT}`);
    })
})


