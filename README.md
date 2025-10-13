# 🛡️ pluggable-schema

**Modular Security & Auth Plugins for Mongoose (TypeScript)**

`pluggable-schema` is a highly extensible Mongoose plugin library for Node.js, enabling dynamic composition of security, authentication, and access control features onto any Mongoose Schema. Built with a focus on modularity and rigorous type safety using TypeScript.

---

## ✨ Core Features

* 🧩 **Modular Architecture:** Add features like JWT, RBAC, and OTP to any schema independently without modifying core user logic.
* 🔑 **Role-Based Access Control (RBAC):** Granular permission checks using `action:resource:scope` (e.g., `update:post:own`) and essential resource ownership validation.
* 🔒 **Dual-Storage OTP:** Supports high-performance OTP storage in Redis (for fast expiry) or standard MongoDB, with built-in brute-force protection.
* 🛡️ **Secure Auth:** Implements industry best practices for password hashing (`bcrypt`) and secure password reset tokens (hashing token before DB storage).

---

## 🚀 Installation

```bash
npm install pluggable-schema mongoose bcrypt jsonwebtoken
```

> Optional: Install your preferred Redis client (e.g., `ioredis`) if using Redis OTP.

---

## ⚙️ Setup Example

```ts
import { Schema, model } from 'mongoose';
import { UserSchemaPlugin, rbacSchemaPlugin, otpSchemaPlugin, saveIn } from 'pluggable-schema';

// Initialize Redis client if using Redis OTP
const yourRedisClientInstance = { /* ... */ }; 

const userSchema = new Schema({
    name: String,
    email: String,
    password: String,
    role: String
});

// 1️⃣ Core Auth and JWT
userSchema.plugin(UserSchemaPlugin, {
    jwtSecret: process.env.JWT_SECRET,
    jwtOptions: { forAccessToken: { expiresIn: '15m' } },
    addResetToken: { enable: true, expiresIn: 3600000 } // 1 hour expiry
});

// 2️⃣ Role-Based Access Control (RBAC)
userSchema.plugin(rbacSchemaPlugin);

// 3️⃣ OTP (using Redis for low-latency)
userSchema.plugin(otpSchemaPlugin, {
    saveIn: saveIn.REDIS,
    email: 'user@example.com',
    redisClient: yourRedisClientInstance
});

export const User = model('User', userSchema);
```

---

## 🔒 Category I: Authentication & Token Management (`UserSchemaPlugin`)

**Methods added to User Document:**

| Method                                 | Description                                                                         | Returns              |
| -------------------------------------- | ----------------------------------------------------------------------------------- | -------------------- |
| `user.generateAccessToken()`           | Generates a signed JWT access token.                                                | `string` (JWT)       |
| `user.isPasswordCorrected(password)`   | Compares the plain input password with the stored hash using bcrypt.                | `Promise<boolean>`   |
| `user.generateResetPasswordToken()`    | Generates a raw token, stores its SHA-256 hash securely, and returns the raw token. | `string` (Raw Token) |
| `user.verifyResetPasswordToken(token)` | Verifies the raw token against the stored hash and checks for expiration.           | `boolean`            |

**Example Usage: Auth**

```ts
// Login Controller
const user = await User.findOne({ email });
if (user && await user.isPasswordCorrected(password)) {
    const token = user.generateAccessToken();
    // Send token to client
}

// Password Reset
const rawToken = user.generateResetPasswordToken();
// Email rawToken to user
await user.save();
```

---

## 🔑 Category II: Role-Based Access Control (RBAC)

### A. User Document Methods

| Method                                       | Description                                                                           | Returns          |         |
| -------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------- | ------- |
| `user.hasPermission(perm, resource?, opts?)` | Checks if the user's role grants the required permission, including ownership checks. | `Promise<boolean | Error>` |
| `user.setRole(roleName)`                     | Sets the role field on the user document.                                             | `void`           |         |

### B. RBAC Middleware (Express)

```ts
import { rbacMiddleware } from 'pluggable-schema/rbac/middleware';
import PostModel from './models/Post';

// Example: 'any' scope
app.get('/api/admin/logs', rbacMiddleware('read:logs:any'), (req, res) => {
    // Only users with 'read:logs:any' can access
});

// Example: 'own' scope with resource fetching
app.put('/api/post/:id', rbacMiddleware(
    'update:post:own', 
    async (req) => await PostModel.findById(req.params.id),
    { ownerField: 'authorId' }
), (req, res) => {
    // Update the post
});
```

---

## 📱 Category III: One-Time Password (OTP) Management (`otpSchemaPlugin`)

**Methods added to User Document:**

| Method                                 | Description                                                                   | Returns                                         |
| -------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------- |
| `user.generateOtp(length, otpOptions)` | Generates a numeric OTP, saves it (Redis or DB), and handles TTL and context. | `Promise<string>`                               |
| `user.verifyOtp(otp, context)`         | Checks OTP, verifies context, expiry, and tracks attempts.                    | `Promise<{ success: boolean; error?: string }>` |

**Example Usage: OTP**

```ts
// Request OTP
const otp = await user.generateOtp(6, {
    context: '2FA_LOGIN',
    expiresIn: 300, // 5 minutes
    maxAttempt: 3
});
// Send OTP to user

// Verify OTP
const { success, error } = await user.verifyOtp(inputOtp, '2FA_LOGIN');
if (success) {
    // OTP valid ✅
} else {
    // Handle error ❌
}
```

---

## ⚖️ License

MIT License
