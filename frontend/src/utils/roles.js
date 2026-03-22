export const ADMIN_ROLES = ["org_admin", "super_admin"];

export function isAdminRole(role) {
  return ADMIN_ROLES.includes(role);
}
