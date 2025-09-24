import { SignOptions } from 'jsonwebtoken';

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
     * Enable OTP (One-Time Password) functionality.
     * Can be a boolean or an object with enable flag and expiration time.
     * Optional.
     */
    enabledOtp?: boolean | options;

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

    otp?: number;

    otpExpiresIn?: number;

    /**
     * Generates a numeric OTP of the specified length and sets expiration.
     * @param {number} length - Number of digits in the OTP.
     * @returns {number} The generated OTP.
     */
    generateOtp?(length: number): number;

    /**
     * Verifies if the provided OTP matches the stored OTP and is not expired.
     * @param {number} otp - OTP to verify.
     * @returns {boolean} True if OTP is valid, else false.
     */
    verifyOtp?(otp: number): boolean;

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

    save(): void
}

export { UserDocument, UserSchemaPluginInterface, options, jwtOptions }
