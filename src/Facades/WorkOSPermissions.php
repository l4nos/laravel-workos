<?php

declare(strict_types=1);

namespace LaravelWorkOS\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * WorkOSPermissions Facade
 * 
 * Provides convenient static access to WorkOS permission and role management.
 * 
 * @method static array getUserPermissions(string $userId, string $organizationId = null)
 * @method static array getUserRoles(string $userId, string $organizationId = null)
 * @method static bool userHasPermission(string $userId, string $permission, string $organizationId = null)
 * @method static bool userHasRole(string $userId, string $role, string $organizationId = null)
 * @method static bool userHasAnyPermission(string $userId, array $permissions, string $organizationId = null)
 * @method static bool userHasAllPermissions(string $userId, array $permissions, string $organizationId = null)
 * @method static array getOrganizationPermissions(string $organizationId)
 * @method static array getOrganizationRoles(string $organizationId)
 * @method static array getPermissionHierarchy(string $organizationId = null)
 * @method static array expandPermissions(array $permissions, string $organizationId = null)
 * @method static void grantUserPermission(string $userId, string $permission, string $organizationId = null)
 * @method static void revokeUserPermission(string $userId, string $permission, string $organizationId = null)
 * @method static void assignUserRole(string $userId, string $role, string $organizationId = null)
 * @method static void removeUserRole(string $userId, string $role, string $organizationId = null)
 * @method static void clearUserPermissionsCache(string $userId)
 * @method static void clearOrganizationPermissionsCache(string $organizationId)
 * @method static array validatePermissions(array $permissions)
 * @method static array normalizePermissions(array $permissions)
 * 
 * @see \LaravelWorkOS\Services\PermissionService
 */
class WorkOSPermissions extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'workos.permissions';
    }
}