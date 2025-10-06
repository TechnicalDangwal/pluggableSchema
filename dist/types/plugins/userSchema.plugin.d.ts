import { Schema } from "mongoose";
import { UserSchemaPluginInterface } from "../types";
/**
 * Mongoose plugin adding JWT auth, password hashing, OTP, and reset token functionality.
 *
 * @param {Schema} schema - Mongoose schema to enhance
 * @param {UserSchemaPluginInterface} options - Plugin configuration options
 */
export declare function UserSchemaPlugin(schema: Schema, options: UserSchemaPluginInterface): void;
