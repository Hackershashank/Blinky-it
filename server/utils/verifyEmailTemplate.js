const verifyEmailTemplate = ({ name, url }) => {
  return `<div>
    <p>Dear ${name}</p>
    <p>Thank you for registering at Blinkyit.</p>
    <a href="${url}" style="color:white;background:#071263;margin-top:10px;padding:20px;display-block;text-decoration:none;">
      Verify Email
    </a>
  </div>`;
};
export default verifyEmailTemplate