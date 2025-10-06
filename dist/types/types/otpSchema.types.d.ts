import { RedisClientType } from "./redisClient.types";
/**
 * Defines the structure for OTP configuration.
 */
interface otpType {
    /**
     * Context in which OTP is being used (e.g., "login", "signup").
     */
    context: string;
    /**
     * Maximum number of allowed verification attempts.
     */
    maxAttempt: number;
    /**
     * Expiration time of the OTP in seconds.
     */
    expiresIn: Date | number;
}
/**
 * Enum representing where OTP data should be saved: Redis or MongoDB.
 */
declare enum saveIn {
    /**
     * Store OTP in Redis.
     */
    REDIS = "redis",
    /**
     * Store OTP in MongoDB.
     */
    DB = "DB"
}
/**
 * Interface for plugin configuration when saving OTP in Redis.
 */
interface saveInRedis {
    /**
     * Save location set to Redis.
     */
    saveIn: saveIn.REDIS;
    /**
     * Redis client instance used for storing/retrieving OTP.
     */
    redisClient: RedisClientType;
    /**
     * Email address used as a key or part of key in Redis.
     */
    email: string;
}
/**
 * Interface for plugin configuration when saving OTP in MongoDB.
 */
interface saveInDB {
    /**
     * Save location set to MongoDB.
     */
    saveIn: saveIn.DB;
}
/**
 * Type for OTP plugin configuration — either Redis or MongoDB.
 */
type otpSchemaPluginInterface = saveInRedis | saveInDB;
/**
 * Extended Mongoose Document interface for models using OTP functionality.
 */
interface otpDocument extends Document {
    /**
     * Generates a numeric OTP of the specified length and sets expiration.
     *
     * @param {number} length - Number of digits in the OTP.
     * @param {otpType} enabledOtp - OTP configuration options.
     * @returns {number} The generated OTP.
     */
    generateOtp(length: number, enabledOtp: otpType): number;
    /**
     * Verifies if the provided OTP matches the stored OTP and is not expired.
     *
     * @param {string} otp - OTP to verify.
     * @param {string} context - Context in which OTP is being verified.
     * @returns {Promise<{ success: boolean; error?: string }>} True if OTP is valid, otherwise false.
     */
    verifyOtp(otp: string, context: string): Promise<{
        success: boolean;
        error?: string;
    }>;
    /**
     * Optional field containing OTP metadata and the OTP value itself.
     */
    otp?: otpType & {
        /**
         * The actual OTP value.
         */
        otp: string;
    };
    /**
     * Saves the document to the database.
     */
    save(): void;
    /**
     * Marks a given field as modified (required when updating nested fields).
     *
     * @param {string} field - The field to mark as modified.
     */
    markModified: (field: string) => void;
}
export { otpDocument, otpSchemaPluginInterface, otpType, saveIn };
