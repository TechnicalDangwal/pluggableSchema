import { RoleModel } from "../models";
import { HasPermissionOptions, RoleDocument } from "../types";

async function hasPermission(this: RoleDocument,
    requestedPermission: string,
    resource?: any,
    options: HasPermissionOptions = {}
): Promise<boolean> {
    const user: any = this;
    // No role means no permissions
    if (!user.role) return false;

    // Fetch role details from DB
    const role = await RoleModel.findOne({ name: user.role }).lean();
    if (!role) return false;

    const permissions = role.permissions || [];

    // Split permission into parts: "action:resource:scope"
    const [reqAction, reqResource] = requestedPermission.split(":");

    const hasAnyPermission = permissions.includes(`${reqAction}:${reqResource}:any`)
    if (hasAnyPermission) return true;

    const hasOwnPermission = permissions.includes(`${reqAction}:${reqResource}:own`)
    if (!hasOwnPermission) return false;
    // If scope is 'own', validate ownership of the resource
    const ownerField = options.ownerField || "ownerId";

    if (!resource[ownerField]) {
        throw new Error(`Resource missing ownership field '${ownerField}'`);
    }

    return user._id.toString() === resource[ownerField].toString();
};

export { hasPermission };