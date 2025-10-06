import { Document, Model } from "mongoose";
/**
 * Represents a Role document in the database.
 *
 * A Role defines a set of permissions assigned to users, typically used in
 * role-based access control (RBAC) systems. Each role has a unique name and
 * an array of permission strings in the format: "action:resource:scope".
 *
 * Example permission: "update:post:own"
 */
interface RoleDocument extends Document {
    /** The unique name of the role (e.g., "admin", "editor", "user"). */
    name: string;
    /**
     * An array of permission strings assigned to this role.
     * Format: "action:resource:scope" (e.g., "read:post:any")
     */
    permissions: string[];
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
export { RoleDocument, RoleModelType, HasPermissionOptions, GetResourceFn };
