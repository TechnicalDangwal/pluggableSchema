import { Schema } from "mongoose";
import bcrypt from 'bcrypt';
import { UserDocument, UserSchemaPluginInterface } from "../types";
import { generateAccessToken, generateOtp, generateRefreshToken, generateResetPasswordToken, isPasswordCorrected, verifyOtp, verifyResetPasswordToken } from "../utils";
import crypto from 'crypto';

/**
 * Mongoose plugin adding JWT auth, password hashing, OTP, and reset token functionality.
 *
 * @param {Schema} schema - Mongoose schema to enhance
 * @param {UserSchemaPluginInterface} options - Plugin configuration options
 */
export function UserSchemaPlugin(schema: Schema, options: UserSchemaPluginInterface) {
    const { jwtOptions, jwtSecret, enabledOtp, addResetToken } = options;

    /**
     * Pre-save hook to hash password if it is modified.
     */
    schema.pre("save", async function (next: () => void) {
        if (this.isModified("password")) {
            this.password = await bcrypt.hash(this.password, 10);
        }
        next();
    });

    schema.methods.generateAccessToken = function (this: UserDocument) {
        return generateAccessToken.call(this, jwtSecret, jwtOptions.forAccessToken)
    }
    if (jwtOptions?.forRefreshToken?.expiresIn) {
        if (!schema.path('refreshToken')) {
            schema.add({
                refreshToken: {
                    type: String,
                    required: false
                }
            });
        }

        schema.methods.generateRefreshToken = function (this: UserDocument) {
            return generateRefreshToken.call(this, jwtSecret, jwtOptions.forRefreshToken)

        }
    }

    schema.methods.isPasswordCorrected = async function (this: UserDocument, password: string) {
        return await isPasswordCorrected.call(this, password)
    }
    if (enabledOtp != undefined) {
        if (!schema.path('otp')) {
            schema.add({
                otp: {
                    type: Number,
                    required: false
                },
                otpExpiresIn: {
                    type: Date,
                    required: false
                }
            });
        }
    }
    schema.methods.generateOtp = function (this: UserDocument, length: number): number {
        return generateOtp.call(this, length, enabledOtp!);
    };

    schema.methods.verifyOtp = function (this: UserDocument, otp: number): boolean {
        return verifyOtp.call(this, otp);
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

        schema.methods.generateResetPasswordToken = function (this: UserDocument) {
            return generateResetPasswordToken.call(this, addResetToken)
        }

        schema.methods.verifyResetPasswordToken = function(this: UserDocument, token: string){
            return verifyResetPasswordToken.call(this,token)
        }
    }
}
