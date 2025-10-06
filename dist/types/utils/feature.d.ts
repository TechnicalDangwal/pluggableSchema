import { options, otpDocument, otpType, UserDocument } from "../types";
import { SignOptions } from 'jsonwebtoken';
import { RedisClientType } from "../types/redisClient.types";
/**
 * Generates a numeric OTP of given length and sets expiry.
 * @param {number} length - OTP digit length
 * @param {otpType} enabledOtp - otp options
 * @returns {number} Generated OTP
 */
declare function generateOtp(this: otpDocument, length: number, enabledOtp: otpType, email: string | undefined, redisClient: RedisClientType | undefined): Promise<string>;
/**
 * Verifies if OTP matches and is not expired.
 * @param {number} otp - OTP to verify
 * @returns {boolean} True if valid OTP
 */
declare function verifyOtp(this: otpDocument, otp: string, email: string | undefined, redisClient: RedisClientType | undefined): Promise<{
    success: boolean;
    error?: string;
}>;
/**
 * Generates a JWT refresh token, saves it on user document, and returns it.
 * @returns {string} JWT refresh token
 */
declare function generateRefreshToken(this: UserDocument, jwtSecret: string, options?: SignOptions): string;
/**
 * Generates a JWT access token with configured expiry.
 * @returns {string} JWT access token
 */
declare function generateAccessToken(this: UserDocument, jwtSecret: string, options?: SignOptions): string;
/**
 * Checks if provided plain password matches hashed password.
 * @param {string} password - Password to verify
 * @returns {Promise<boolean>} True if password matches
 */
declare function isPasswordCorrected(this: UserDocument, password: string): Promise<boolean>;
/**
 * Generates a reset password token using crypto and stores a hashed version.
 * @returns {string} Raw reset password token (to be sent to user)
 */
declare function generateResetPasswordToken(this: UserDocument, addResetToken: boolean | options): string;
/**
 * Verifies the reset password token by comparing its hash and expiration.
 * @param {string} token - Raw token received from user
 * @returns {boolean} True if token is valid and not expired
 */
declare function verifyResetPasswordToken(this: UserDocument, token: string): boolean;
export { generateOtp, verifyOtp, generateRefreshToken, generateAccessToken, isPasswordCorrected, generateResetPasswordToken, verifyResetPasswordToken };
