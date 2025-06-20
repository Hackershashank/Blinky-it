import { Resend } from 'resend';

import dotenv from 'dotenv';
dotenv.config();

if(!process.env.RESEND_API){
    console.log("Provide RESEND_API in side the .env file")
}

const resend = new Resend(process.env.RESEND_API);

const sendEmail = async ({ sendTo, subject, html }) => {
  try {
    const { data, error } = await resend.emails.send({
      from: 'Blinkyit <onboarding@resend.dev>',
      to: sendTo,
      subject: subject,
      html: html,
    });

    if (error) {
      console.error("Error sending email:", error);
      return null;
    }

    console.log("Email sent successfully:", data);
    return data;

  } catch (err) {
    console.error("Unexpected error in sendEmail:", err);
    return null;
  }
};

export default sendEmail;
