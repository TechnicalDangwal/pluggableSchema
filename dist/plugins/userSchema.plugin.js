import bcrypt from 'bcrypt';
import { generateAccessToken, generateRefreshToken, generateResetPasswordToken, isPasswordCorrected, verifyResetPasswordToken } from "../utils";
/**
 * Mongoose plugin adding JWT auth, password hashing, OTP, and reset token functionality.
 *
 * @param {Schema} schema - Mongoose schema to enhance
 * @param {UserSchemaPluginInterface} options - Plugin configuration options
 */
export function UserSchemaPlugin(schema, options) {
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
