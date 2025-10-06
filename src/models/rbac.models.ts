import  { model, Schema } from "mongoose";
import { RoleDocument, RoleModelType } from "../types";

const RoleSchema = new Schema<RoleDocument>({
  name: { type: String, required: true, unique: true },
  permissions: { type: [String], default: [] },
});

/**
 * Creates a new role with a set of permissions.
 * Throws an error if the role already exists.
 */
RoleSchema.statics.createRole = async function (
  name: string,
  permissions: string[]
): Promise<RoleDocument> {
  // console.log(this.findOne({name}),'this');
  
  const existing = await this.findOne({ name });
  console.log(existing,'existing');
  
  if (existing) {
    throw new Error(`Role '${name}' already exists`);
  }

  return this.create({ name, permissions });
};

/**
 * Retrieves a role by its name.
 * Returns null if the role is not found.
 */
RoleSchema.statics.getRoleByName = async function (
  name: string
): Promise<RoleDocument | null> {
  return this.findOne({ name });
};

export const RoleModel = model<RoleDocument, RoleModelType>("Role", RoleSchema);

