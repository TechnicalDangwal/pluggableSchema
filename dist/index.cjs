'use strict';

var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');
var mongoose = require('mongoose');

/**
 * Generates a JWT refresh token, saves it on user document, and returns it.
 * @returns {string} JWT refresh token
 */
function generateRefreshToken(jwtSecret, options) {
    const token = jwt.sign({ _id: this._id }, jwtSecret, options);
    this.refreshToken = token;
    return token;
}
/**
 * Generates a JWT access token with configured expiry.
 * @returns {string} JWT access token
 */
function generateAccessToken(jwtSecret, options) {
    return jwt.sign({ _id: this._id }, jwtSecret, options);
}
/**
 * Checks if provided plain password matches hashed password.
 * @param {string} password - Password to verify
 * @returns {Promise<boolean>} True if password matches
 */
async function isPasswordCorrected(password) {
    return await bcrypt.compare(password, this.password);
}
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
/**
 * Verifies if OTP matches and is not expired.
 * @param {number} otp - OTP to verify
 * @returns {boolean} True if valid OTP
 */
async function verifyOtp(otp, context, email, redisClient) {
    try {
        if (redisClient != undefined) {
            const data = await redisClient.get(`otp:${email}`);
            if (!data) {
                return { success: false, error: 'OTP expired or not found' };
            }
            const redisOtp = JSON.parse(data);
            if (redisOtp.context != context) {
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
        if (this.otp.context != context) {
            return { success: false, error: 'OTP context mismatch' };
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

const RoleSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    permissions: { type: [String], default: [] },
});
/**
 * Creates a new role with a set of permissions.
 * Throws an error if the role already exists.
 */
RoleSchema.statics.createRole = async function (name, permissions) {
    // console.log(this.findOne({name}),'this');
    const existing = await this.findOne({ name });
    console.log(existing, 'existing');
    if (existing) {
        throw new Error(`Role '${name}' already exists`);
    }
    return this.create({ name, permissions });
};
/**
 * Retrieves a role by its name.
 * Returns null if the role is not found.
 */
RoleSchema.statics.getRoleByName = async function (name) {
    return this.findOne({ name });
};
const RoleModel = mongoose.model("Role", RoleSchema);

async function hasPermission(requestedPermission, resource, options = {}) {
    const user = this;
    // No role means no permissions
    if (!user.role)
        return false;
    // Fetch role details from DB
    const role = await RoleModel.findOne({ name: user.role }).lean();
    if (!role)
        return false;
    const permissions = role.permissions || [];
    // Split permission into parts: "action:resource:scope"
    const [reqAction, reqResource] = requestedPermission.split(":");
    const hasAnyPermission = permissions.includes(`${reqAction}:${reqResource}:any`);
    if (hasAnyPermission)
        return true;
    const hasOwnPermission = permissions.includes(`${reqAction}:${reqResource}:own`);
    if (!hasOwnPermission)
        return false;
    // If scope is 'own', validate ownership of the resource
    const ownerField = options.ownerField || "ownerId";
    if (!resource[ownerField]) {
        throw new Error(`Resource missing ownership field '${ownerField}'`);
    }
    return user._id.toString() === resource[ownerField].toString();
}

/**
 * Mongoose plugin adding JWT auth, password hashing, OTP, and reset token functionality.
 *
 * @param {Schema} schema - Mongoose schema to enhance
 * @param {UserSchemaPluginInterface} options - Plugin configuration options
 */
function UserSchemaPlugin(schema, options) {
    const { jwtOptions, jwtSecret, addResetToken } = options;
    /**
     * Pre-save hook to hash password if it is modified.
     */
    schema.pre("save", async function (next) {
        if (this.isModified("password")) {
            this.password = await bcrypt.hash(this.password, 10);
        }
        next();
    });
    schema.methods.generateAccessToken = function () {
        return generateAccessToken.call(this, jwtSecret, jwtOptions.forAccessToken);
    };
    if (jwtOptions?.forRefreshToken?.expiresIn) {
        if (!schema.path('refreshToken')) {
            schema.add({
                refreshToken: {
                    type: String,
                    required: false
                }
            });
        }
        schema.methods.generateRefreshToken = function () {
            return generateRefreshToken.call(this, jwtSecret, jwtOptions.forRefreshToken);
        };
    }
    schema.methods.isPasswordCorrected = async function (password) {
        return await isPasswordCorrected.call(this, password);
    };
    if (addResetToken != undefined) {
        if (!schema.path('resetPasswordToken')) {
            schema.add({
                resetPasswordToken: {
                    type: String,
                    required: false
                },
                resetPasswordExpiresIn: {
                    type: Date,
                    required: false
                }
            });
        }
        schema.methods.generateResetPasswordToken = function () {
            return generateResetPasswordToken.call(this, addResetToken);
        };
        schema.methods.verifyResetPasswordToken = function (token) {
            return verifyResetPasswordToken.call(this, token);
        };
    }
}

/**
 * Enum representing where OTP data should be saved: Redis or MongoDB.
 */
exports.saveIn = void 0;
(function (saveIn) {
    /**
     * Store OTP in Redis.
     */
    saveIn["REDIS"] = "redis";
    /**
     * Store OTP in MongoDB.
     */
    saveIn["DB"] = "DB";
})(exports.saveIn || (exports.saveIn = {}));

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
function otpSchemaPlugin(schema, options) {
    // If storing OTP in MongoDB, ensure the schema has an 'otp' field
    if (options.saveIn === exports.saveIn.DB) {
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
    schema.methods.generateOtp = function (length, otpOptions) {
        return generateOtp.call(this, length, otpOptions, options.saveIn === exports.saveIn.REDIS ? options.email : undefined, options.saveIn === exports.saveIn.REDIS ? options.redisClient : undefined);
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
    schema.methods.verifyOtp = function (otp, context) {
        return verifyOtp.call(this, otp, context, options.saveIn === exports.saveIn.REDIS ? options.email : undefined, options.saveIn === exports.saveIn.REDIS ? options.redisClient : undefined);
    };
}

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
function rbacSchemaPlugin(schema) {
    // Ensure the schema has a 'role' field
    if (!schema.path("role")) {
        schema.add({ role: { type: String, required: false } });
    }
    /**
     * Checks if the user has a specific permission, optionally verifying ownership.
     * @instance
     * @param {string} requestedPermission - The permission to check in the format `action:resource`.
     * @param {any} [resource] - Optional resource object used to verify ownership when scope is `'own'`.
     * @param {HasPermissionOptions} [options] - Options to customize the ownership field.
     *
     * @returns {Promise<boolean>} - Resolves to `true` if permission is granted, otherwise `false`.
     */
    schema.methods.hasPermission = async function (requestedPermission, resource, options = {}) {
        return hasPermission.call(this, requestedPermission, resource, options);
    };
    /**
   * INSTANCE METHOD: Set the user's role
   */
    schema.methods.setRole = function (roleName) {
        this.role = roleName;
    };
    /**
     * STATIC METHOD: Get all available role names
     */
    schema.statics.getAvailableRoles = async function () {
        const roles = await RoleModel.find({}, "name").lean();
        return roles.map(role => role.name);
    };
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
function rbacMiddleware(requiredPermission, getResource, options = {}) {
    return async function (req, res, next) {
        try {
            const user = req.user;
            if (!user) {
                return res.status(401).json({ error: "Unauthorized: No user attached to request" });
            }
            const resource = getResource ? await getResource(req) : undefined;
            const hasPerm = await user.hasPermission(requiredPermission, resource, options);
            if (hasPerm instanceof Error) {
                return res.status(400).json({ error: hasPerm.message });
            }
            if (!hasPerm) {
                return res.status(403).json({ error: "Forbidden: Insufficient permission" });
            }
            next();
        }
        catch (error) {
            next(error);
        }
    };
}

exports.RoleModel = RoleModel;
exports.UserSchemaPlugin = UserSchemaPlugin;
exports.otpSchemaPlugin = otpSchemaPlugin;
exports.rbacMiddleware = rbacMiddleware;
exports.rbacSchemaPlugin = rbacSchemaPlugin;
