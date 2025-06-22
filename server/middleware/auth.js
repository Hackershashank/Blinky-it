import jwt from 'jsonwebtoken'
const auth=async(req,res,next)=>{
    try {
        const token=req.cookies?.accessToken||req?.header?.authorization?.split(" ")[1] ///["Bearer","token"]
        if(!token){
            return res.status(401).json({
                message:"Provide token"
            })
        }
        // Avoid await for jwt.verify:
        // jwt.verify() is synchronous unless you use a callback. No need for await unless using the callback version.
        // If you want an async version, use promisify from util
        const decode=jwt.verify(token,process.env.SECRET_KEY_ACCESS_TOKEN);
        if(!decode){
            return res.status(401).json({
                message:'unauthorized access',
                error:true,
                success:false
            })
        }
        req.userId=decode.id;
        next();
    } catch (error) {
        return res.status(401).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
    
}
export default auth