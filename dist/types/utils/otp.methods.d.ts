import { otpDocument, otpType } from "../types";
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
declare function verifyOtp(this: otpDocument, otp: string, context: string, email: string | undefined, redisClient: RedisClientType | undefined): Promise<{
    success: boolean;
    error?: string;
}>;
export { generateOtp, verifyOtp };
