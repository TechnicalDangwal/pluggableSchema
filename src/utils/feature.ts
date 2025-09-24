import { options, UserDocument } from "../types";
import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

/**
 * Generates a numeric OTP of given length and sets expiry.
 * @param {number} length - OTP digit length
 * @returns {number} Generated OTP
 */
function generateOtp(this: UserDocument, length: number, enabledOtp: boolean | options) {
    const digits = '0123456789';
    const otp = Array.from({ length }, () =>
        digits[Math.floor(Math.random() * digits.length)]
    ).join('');

    this.otp = Number(otp);
    this.otpExpiresIn = typeof enabledOtp === "boolean" ? Date.now() + 5 * 60 * 1000 : enabledOtp.expiresIn;
    this.save();
    return Number(otp);
};

/**
 * Verifies if OTP matches and is not expired.
 * @param {number} otp - OTP to verify
 * @returns {boolean} True if valid OTP
 */
function verifyOtp(this: UserDocument, otp: number) {
    if (new Date(this.otpExpiresIn!).getTime() > Date.now()) {
        return this.otp === otp;
    }
    return false;
};

/**
 * Generates a JWT refresh token, saves it on user document, and returns it.
 * @returns {string} JWT refresh token
 */
function generateRefreshToken(this: UserDocument, jwtSecret: string, options?: SignOptions) {
    const token = jwt.sign(
        { _id: this._id },
        jwtSecret,
        options
    );
    this.refreshToken = token;
    return token;
};

/**
 * Generates a JWT access token with configured expiry.
 * @returns {string} JWT access token
 */
function generateAccessToken(this: UserDocument, jwtSecret: string, options?: SignOptions) {
    return jwt.sign(
        { _id: this._id },
        jwtSecret,
        options
    );
};

/**
 * Checks if provided plain password matches hashed password.
 * @param {string} password - Password to verify
 * @returns {Promise<boolean>} True if password matches
 */
async function isPasswordCorrected(this: UserDocument, password: string) {
    return await bcrypt.compare(password, this.password);
};

/**
 * Generates a reset password token using crypto and stores a hashed version.
 * @returns {string} Raw reset password token (to be sent to user)
 */
function generateResetPasswordToken(this: UserDocument, addResetToken: boolean | options): string {
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
};

/**
 * Verifies the reset password token by comparing its hash and expiration.
 * @param {string} token - Raw token received from user
 * @returns {boolean} True if token is valid and not expired
 */
function verifyResetPasswordToken(this: UserDocument, token: string): boolean {
    if (!this.resetPasswordToken || !this.resetPasswordExpiresIn) return false;
    if (new Date(this.resetPasswordExpiresIn).getTime() < Date.now()) return false;

    // Hash the incoming token
    const hashedInput = crypto.createHash('sha256').update(token).digest('hex');

    // Compare stored and input hashes
    return hashedInput === this.resetPasswordToken;
};
export { generateOtp, verifyOtp, generateRefreshToken, generateAccessToken, isPasswordCorrected, generateResetPasswordToken, verifyResetPasswordToken }