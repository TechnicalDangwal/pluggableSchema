import { RoleModel } from "../models";
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
     *
     * @param {string} requestedPermission - The permission to check in the format `action:resource`.
     * @param {any} [resource] - Optional resource object used to verify ownership when scope is `'own'`.
     * @param {HasPermissionOptions} [options] - Options to customize the ownership field.
     *
     * @returns {Promise<boolean>} - Resolves to `true` if permission is granted, otherwise `false`.
     */
    schema.methods.hasPermission = async function (requestedPermission, resource, options = {}) {
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
        console.log(resource, 'resource');
        if (!resource[ownerField]) {
            throw new Error(`Resource missing ownership field '${ownerField}'`);
        }
        return user._id.toString() === resource[ownerField].toString();
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
