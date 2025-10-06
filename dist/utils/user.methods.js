import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
/**
 * Generates a JWT refresh token, saves it on user document, and returns it.
 * @returns {string} JWT refresh token
 */
function generateRefreshToken(jwtSecret, options) {
    const token = jwt.sign({ _id: this._id }, jwtSecret, options);
    this.refreshToken = token;
    return token;
}
;
/**
 * Generates a JWT access token with configured expiry.
 * @returns {string} JWT access token
 */
function generateAccessToken(jwtSecret, options) {
    return jwt.sign({ _id: this._id }, jwtSecret, options);
}
;
/**
 * Checks if provided plain password matches hashed password.
 * @param {string} password - Password to verify
 * @returns {Promise<boolean>} True if password matches
 */
async function isPasswordCorrected(password) {
    return await bcrypt.compare(password, this.password);
}
;
/**
 * Generates a reset password token using crypto and stores a hashed version.
 * @returns {string} Raw reset password token (to be sent to user)
 */
function generateResetPasswordToken(addResetToken) {
    // Generate a secure random token
    const rawToken = crypto.randomBytes(32).toString('hex');
    // Hash the token using SHA-256 and store in DB
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
    // Determine expiration time
    const expiresInMs = typeof addResetToken === "boolean"
        ? 5 * 60 * 1000 // 5 minutes
        : Number(addResetToken.expiresIn);
    // Save hashed token and expiration
    this.resetPasswordToken = hashedToken;
    this.resetPasswordExpiresIn = expiresInMs;
    // Return the raw token to be emailed to the user
    return rawToken;
}
;
/**
 * Verifies the reset password token by comparing its hash and expiration.
 * @param {string} token - Raw token received from user
 * @returns {boolean} True if token is valid and not expired
 */
function verifyResetPasswordToken(token) {
    if (!this.resetPasswordToken || !this.resetPasswordExpiresIn)
        return false;
    if (new Date(this.resetPasswordExpiresIn).getTime() < Date.now())
        return false;
    // Hash the incoming token
    const hashedInput = crypto.createHash('sha256').update(token).digest('hex');
    // Compare stored and input hashes
    return hashedInput === this.resetPasswordToken;
}
;
export { generateRefreshToken, generateAccessToken, isPasswordCorrected, generateResetPasswordToken, verifyResetPasswordToken };
