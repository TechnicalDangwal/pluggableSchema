import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
/**
 * Generates a numeric OTP of given length and sets expiry.
 * @param {number} length - OTP digit length
 * @param {otpType} enabledOtp - otp options
 * @returns {number} Generated OTP
 */
async function generateOtp(length, enabledOtp, email, redisClient) {
    const digits = '0123456789';
    const otp = Array.from({ length }, () => digits[Math.floor(Math.random() * digits.length)]).join('');
    if (redisClient != undefined) {
        redisClient.setex(`otp:${email}`, enabledOtp.expiresIn, JSON.stringify({
            otp,
            context: enabledOtp.context,
            maxAttempt: enabledOtp.maxAttempt
        }));
        return otp;
    }
    this.otp = {
        otp,
        context: enabledOtp.context,
        expiresIn: new Date(Date.now() + (enabledOtp.expiresIn * 1000)),
        maxAttempt: enabledOtp.maxAttempt
    };
    await this.save();
    return otp;
}
;
/**
 * Verifies if OTP matches and is not expired.
 * @param {number} otp - OTP to verify
 * @returns {boolean} True if valid OTP
 */
async function verifyOtp(otp, email, redisClient) {
    try {
        if (redisClient != undefined) {
            const data = await redisClient.get(`otp:${email}`);
            if (!data) {
                return { success: false, error: 'OTP expired or not found' };
            }
            const redisOtp = JSON.parse(data);
            if (redisOtp.maxAttempt <= 0) {
                await redisClient.del(`otp:${email}`);
                return { success: false, error: 'Maximum attempts exceeded' };
            }
            if (redisOtp.otp.toString() !== otp) {
                redisOtp.maxAttempt -= 1;
                await redisClient.set(`otp:${email}`, JSON.stringify(redisOtp));
                return { success: false, error: 'Incorrect OTP' };
            }
            // Optionally delete OTP after success
            await redisClient.del(`otp:${email}`);
            return { success: true };
        }
        // MongoDB fallback
        if (!this.otp) {
            return { success: false, error: 'OTP not set' };
        }
        const now = Date.now();
        const expiry = new Date(this.otp.expiresIn).getTime();
        if (expiry < now) {
            this.otp = undefined;
            await this.save();
            return { success: false, error: 'OTP expired' };
        }
        if (this.otp.maxAttempt <= 0) {
            this.otp = undefined;
            await this.save();
            return { success: false, error: 'Maximum attempts exceeded' };
        }
        if (this.otp.otp !== otp.toString()) {
            this.otp.maxAttempt -= 1;
            this.markModified('otp');
            await this.save();
            return { success: false, error: 'Incorrect OTP' };
        }
        // Optionally remove OTP after success
        this.otp = undefined;
        await this.save();
        return { success: true };
    }
    catch (err) {
        return { success: false, error: 'Internal server error during OTP verification' };
    }
}
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
export { generateOtp, verifyOtp, generateRefreshToken, generateAccessToken, isPasswordCorrected, generateResetPasswordToken, verifyResetPasswordToken };
