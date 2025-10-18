import { Document as Document$1, Model, Schema } from 'mongoose';
import { SignOptions } from 'jsonwebtoken';
import { Request as Request$1, Response, NextFunction } from 'express';

/**
 * JWT signing options for access and optionally refresh tokens.
 */
type jwtOptions = {
    /**
     * Options used when signing an access token.
     */
    forAccessToken: SignOptions;
    /**
     * Options used when signing a refresh token.
     * Optional.
     */
    forRefreshToken?: SignOptions;
};
/**
 * General feature toggle with expiration setting.
 */
type options = {
    /**
     * Whether the feature is enabled.
     */
    enable: boolean;
    /**
     * Duration in ms until the token expires.
     */
    expiresIn: number;
};
/**
 * Interface for the user schema plugin configuration.
 */
interface UserSchemaPluginInterface {
    /**
     * Secret key used for signing JWT tokens.
     */
    jwtSecret: string;
    /**
     * JWT options for access and optional refresh tokens.
     */
    jwtOptions: jwtOptions;
    /**
     * Enable reset token functionality (e.g., for password reset).
     * Can be a boolean or an object with enable flag and expiration time.
     * Optional.
     */
    addResetToken?: boolean | options;
}
/**
 * Interface for User document instance methods and properties.
 */
interface UserDocument extends Document {
    _id: string;
    refreshToken: string;
    password: string;
    email: string;
    /**
     * Generates a JWT access token valid for the configured expiry.
     * @returns {string} Signed JWT access token.
     */
    generateAccessToken(): string;
    /**
     * Generates a JWT refresh token valid for the configured expiry and saves it.
     * @returns {string} Signed JWT refresh token.
     */
    generateRefreshToken(): string;
    /**
     * Compares the provided plain password with the stored hashed password.
     * @param {string} password - Plain text password to verify.
     * @returns {Promise<boolean>} True if password matches, else false.
     */
    isPasswordCorrected(password: string): Promise<boolean>;
    resetPasswordToken?: string;
    resetPasswordExpiresIn?: number;
    /**
     * Generates a JWT reset password token valid for the configured expiry.
     * @returns {string} Signed JWT reset password token.
     */
    generateResetPasswordToken?(): string;
    /**
     * Verifies if the reset password token is valid and not expired.
     * @param {string} token - Reset password token to verify.
     * @returns {boolean} True if token is valid, else false.
     */
    verifyResetPasswordToken?(token: string): boolean;
    save(): void;
}

interface RedisClientType {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<'OK' | null>;
    del(key: string): Promise<number>;
    setex(key: string, ttlSeconds: number, value: string): Promise<'OK' | null>;
}

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

/**
 * Represents a Role document in the database.
 *
 * A Role defines a set of permissions assigned to users, typically used in
 * role-based access control (RBAC) systems. Each role has a unique name and
 * an array of permission strings in the format: "action:resource:scope".
 *
 * Example permission: "update:post:own"
 */
interface RoleDocument extends Document$1 {
    /** The unique name of the role (e.g., "admin", "editor", "user"). */
    name: string;
    /**
     * An array of permission strings assigned to this role.
     * Format: "action:resource:scope" (e.g., "read:post:any")
     */
    permissions: string[];
    /** The name of the role assigned to the user. Optional field. */
    role?: string;
}
/**
 * Static methods available on the Role model.
 *
 * These allow you to interact with Role documents at the model level,
 * such as creating new roles or fetching existing ones by name.
 */
interface RoleModelType extends Model<RoleDocument> {
    /**
     * Creates a new role with a unique name and an array of permissions.
     *
     * @param name - The name of the role (must be unique).
     * @param permissions - Array of permission strings in the format "action:resource:scope".
     * @returns A promise that resolves to the newly created Role document.
     * @throws Error if a role with the given name already exists.
     */
    createRole(name: string, permissions: string[]): Promise<RoleDocument>;
    /**
     * Finds a role by its name.
     *
     * @param name - The name of the role to retrieve.
     * @returns A promise that resolves to the Role document if found, or `null` if not.
     */
    getRoleByName(name: string): Promise<RoleDocument | null>;
}
/**
 * Options for checking ownership in permission scope.
 */
interface HasPermissionOptions {
    /**
     * Field name in the resource object that represents ownership.
     * Defaults to `"ownerId"` if not specified.
     */
    ownerField?: string;
}
/**
 * Function type to extract a resource object from the Express request.
 * Used to check ownership when scope is 'own'.
 */
type GetResourceFn = (req: Request & {
    user: {
        _id: any;
        hasPermission: (perm: string, res?: any, opts?: HasPermissionOptions) => Promise<boolean | Error>;
    };
}) => any | Promise<any>;

/**
 * Mongoose plugin adding JWT auth, password hashing, OTP, and reset token functionality.
 *
 * @param {Schema} schema - Mongoose schema to enhance
 * @param {UserSchemaPluginInterface} options - Plugin configuration options
 */
declare function UserSchemaPlugin(schema: Schema, options: UserSchemaPluginInterface): void;

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
declare function otpSchemaPlugin(schema: Schema, options: otpSchemaPluginInterface): void;

/**
 * Mongoose schema plugin that adds an RBAC-based `hasPermission` method
 * to a user document.
 *
 * This method allows permission checks based on the user's role and
 * the permissions defined in the corresponding Role document.
 *
 * Permissions follow the format: `"action:resource:scope"` — for example:
 * - `create:post:any`
 * - `update:comment:own`
 *
 * @param {Schema} schema - The Mongoose schema to which the method is added.
 */
declare function rbacSchemaPlugin(schema: Schema): void;

declare const RoleModel: RoleModelType;

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}
/**
 * Express middleware factory to enforce RBAC permissions.
 *
 * @param {string} requiredPermission - The permission string to check, e.g. 'update:post:own'.
 * @param {GetResourceFn} [getResource] - Optional function to extract the resource from the request for ownership checks.
 * @param {HasPermissionOptions} [options] - Optional settings like ownerField.
 *
 * @returns {Function} Express middleware that verifies user permissions.
 *
 * @throws Will respond with 401 if no user is attached to the request.
 * @throws Will respond with 400 if the permission check returns an Error.
 * @throws Will respond with 403 if the user does not have the required permission.
 */
declare function rbacMiddleware(requiredPermission: string, getResource?: GetResourceFn, options?: HasPermissionOptions): (req: Request$1, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>> | undefined>;

export { RoleModel, UserSchemaPlugin, otpSchemaPlugin, rbacMiddleware, rbacSchemaPlugin, saveIn };
export type { GetResourceFn, HasPermissionOptions, RoleDocument, RoleModelType, UserDocument, UserSchemaPluginInterface, jwtOptions, options, otpDocument, otpSchemaPluginInterface, otpType };
