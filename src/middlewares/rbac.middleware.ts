import { Request, Response, NextFunction } from "express";
import { GetResourceFn, HasPermissionOptions } from "../types";

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
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
export function rbacMiddleware(
    requiredPermission: string,
    getResource?: GetResourceFn,
    options: HasPermissionOptions = {}
) {
    return async function (
        req: Request,
        res: Response,
        next: NextFunction
    ) {
        try {
            const user = req.user;

            if (!user) {
                return res.status(401).json({ error: "Unauthorized: No user attached to request" });
            }

            const resource = getResource ? await getResource(req as any) : undefined;

            const hasPerm = await user.hasPermission(requiredPermission, resource, options);

            if (hasPerm instanceof Error) {
                return res.status(400).json({ error: hasPerm.message });
            }
            if (!hasPerm) {
                return res.status(403).json({ error: "Forbidden: Insufficient permission" });
            }

            next();
        } catch (error) {
            next(error);
        }
    };
}
