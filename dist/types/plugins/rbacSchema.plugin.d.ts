import { Schema } from "mongoose";
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
export declare function rbacSchemaPlugin(schema: Schema): void;
