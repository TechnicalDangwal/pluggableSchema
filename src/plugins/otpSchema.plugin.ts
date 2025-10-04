import { Schema } from "mongoose";
import {
    otpDocument,
    otpSchemaPluginInterface,
    otpType,
    saveIn
} from "../types";
import { generateOtp, verifyOtp } from "../utils";

/**
 * A Mongoose schema plugin that adds OTP (One-Time Password) generation and verification methods.
 * Supports storing OTP either in MongoDB or in Redis, based on configuration.
 *
 * @function otpSchemaPlugin
 * @param {Schema} schema - The Mongoose schema to which the OTP methods should be added.
 * @param {otpSchemaPluginInterface} options - Configuration options for OTP behavior.
 * @param {saveIn} options.saveIn - Where to store the OTP: 'DB' (MongoDB) or 'REDIS'.
 * @param {string} [options.email] - The user's email (required if using Redis).
 * @param {RedisClientType} [options.redisClient] - Redis client instance (required if using Redis).
 *
 * @example
 * schema.plugin(otpSchemaPlugin, {
 *   saveIn: saveIn.REDIS,
 *   email: 'user@example.com',
 *   redisClient: redisClientInstance
 * });
 */
export function otpSchemaPlugin(schema: Schema, options: otpSchemaPluginInterface): void {

    // If storing OTP in MongoDB, ensure the schema has an 'otp' field
    if (options.saveIn === saveIn.DB) {
        if (!schema.path('otp')) {
            schema.add({
                otp: {
                    type: Object,
                    required: false
                }
            });
        }
    }

    /**
     * Instance method to generate a one-time password (OTP).
     * Depending on the storage method, it stores OTP in Redis or MongoDB.
     *
     * @method generateOtp
     * @memberof otpDocument
     * @instance
     * @param {number} length - Length of the OTP to generate.
     * @param {otpType} otpOptions - Options such as expiry, hash usage, etc.
     * @returns {Promise<string>} The generated OTP.
     */
    schema.methods.generateOtp = function (
        this: otpDocument,
        length: number,
        otpOptions: otpType
    ): Promise<string> {
        return generateOtp.call(
            this,
            length,
            otpOptions!,
            options.saveIn === saveIn.REDIS ? options.email : undefined,
            options.saveIn === saveIn.REDIS ? options.redisClient : undefined
        );
    };

    /**
     * Instance method to verify a given OTP against stored OTP (in DB or Redis).
     *
     * @method verifyOtp
     * @memberof otpDocument
     * @instance
     * @param {string} otp - The OTP to verify.
     * @returns {Promise<{ success: boolean; error?: string }>} Whether the OTP is valid.
     */
    schema.methods.verifyOtp = function (
        this: otpDocument,
        otp: string,
        context: string,
    ): Promise<{ success: boolean; error?: string }> {
        return verifyOtp.call(
            this,
            otp,
            context,
            options.saveIn === saveIn.REDIS ? options.email : undefined,
            options.saveIn === saveIn.REDIS ? options.redisClient : undefined
        );
    };
}
