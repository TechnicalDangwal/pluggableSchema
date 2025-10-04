import { otpDocument, otpType } from "../types";
import { RedisClientType } from "../types/redisClient.types";

/**
 * Generates a numeric OTP of given length and sets expiry.
 * @param {number} length - OTP digit length
 * @param {otpType} enabledOtp - otp options
 * @returns {number} Generated OTP
 */
async function generateOtp(this: otpDocument, length: number, enabledOtp: otpType, email: string | undefined, redisClient: RedisClientType | undefined) {
    const digits = '0123456789';
    const otp = Array.from({ length }, () =>
        digits[Math.floor(Math.random() * digits.length)]
    ).join('');

    if (redisClient != undefined) {
        redisClient.setex(`otp:${email}`, enabledOtp.expiresIn as number, JSON.stringify({
            otp,
            context: enabledOtp.context,
            maxAttempt: enabledOtp.maxAttempt
        }))
        return otp
    }
    this.otp = {
        otp,
        context: enabledOtp.context,
        expiresIn: new Date(Date.now() + ((enabledOtp.expiresIn as number) * 1000)),
        maxAttempt: enabledOtp.maxAttempt

    };
    await this.save()
    return otp;
};

/**
 * Verifies if OTP matches and is not expired.
 * @param {number} otp - OTP to verify
 * @returns {boolean} True if valid OTP
 */
async function verifyOtp(
    this: otpDocument,
    otp: string,
    context: string,
    email: string | undefined,
    redisClient: RedisClientType | undefined,
): Promise<{ success: boolean; error?: string }> {
    try {
        if (redisClient != undefined) {
            const data = await redisClient.get(`otp:${email}`);

            if (!data) {
                return { success: false, error: 'OTP expired or not found' };
            }

            const redisOtp = JSON.parse(data) as otpType & { otp: number };

            if(redisOtp.context != context) {
                return { success: false, error: 'OTP context mismatch' };
            }
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
        if(this.otp.context != context) {
            return { success: false, error: 'OTP context mismatch' };
        }
        if (this.otp.maxAttempt <= 0) {
            this.otp = undefined
            await this.save()
            return { success: false, error: 'Maximum attempts exceeded' }
        }
        if (this.otp.otp !== otp.toString()) {
            this.otp.maxAttempt -= 1;
            this.markModified('otp')
            await this.save();
            return { success: false, error: 'Incorrect OTP' };
        }

        // Optionally remove OTP after success
        this.otp = undefined;
        await this.save();

        return { success: true };

    } catch (err) {
        return { success: false, error: 'Internal server error during OTP verification' };
    }
}

export { generateOtp, verifyOtp }