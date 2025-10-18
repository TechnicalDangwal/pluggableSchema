import { RoleModel } from "../models";
import { hasPermission } from "../utils";
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
export function rbacSchemaPlugin(schema) {
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
