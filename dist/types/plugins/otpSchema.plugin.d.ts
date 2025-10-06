import { Schema } from "mongoose";
import { otpSchemaPluginInterface } from "../types";
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
export declare function otpSchemaPlugin(schema: Schema, options: otpSchemaPluginInterface): void;
