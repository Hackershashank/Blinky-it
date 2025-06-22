const forgotPasswordTemplate=({name,otp})=>{
    return `
    <div>
        <p>Dear, ${name}</p>
        <p>You are requested a password reset. Please use the following OTP code
        to reset your password.</p>
        <div style="background:yellow;font-size:20px;padding:20px;text-align:center;font-weight:800;">
            ${otp}
        </div>
        <p>This otp is valid for 1 hr only. Enter this otp in the blinkyit
        website to proceed with resetting your password.</p>
        <br/>
        </br>
        <p>Thanks</p>
        <p>Blinkyit</p>
    </div>
    `
}
export default forgotPasswordTemplate