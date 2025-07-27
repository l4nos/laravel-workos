<?php

declare(strict_types=1);

namespace LaravelWorkOS\Services;

use Exception;
use Illuminate\Cache\CacheManager;
use RuntimeException;

class PermissionService
{
    protected WorkOSService $workos;
    protected array $config;
    protected ?CacheManager $cache;

    public function __construct(
        WorkOSService $workos,
        array $config,
        ?CacheManager $cache = null
    ) {
        $this->workos = $workos;
        $this->config = $config;
        $this->cache = $cache;
    }

    /**
     * Get user permissions with optional caching.
     */
    public function getUserPermissions(string $userId, bool $useCache = true): array
    {
        if (!$useCache || !$this->cache) {
            return $this->fetchUserPermissions($userId);
        }

        $cacheKey = $this->getCacheKey('user_permissions', $userId);
        $ttl = $this->config['cache']['ttl']['permissions'] ?? 1800;

        return $this->cache->remember($cacheKey, $ttl, function () use ($userId) {
            return $this->fetchUserPermissions($userId);
        });
    }

    /**
     * Get user roles with optional caching.
     */
    public function getUserRoles(string $userId, bool $useCache = true): array
    {
        if (!$useCache || !$this->cache) {
            return $this->fetchUserRoles($userId);
        }

        $cacheKey = $this->getCacheKey('user_roles', $userId);
        $ttl = $this->config['cache']['ttl']['permissions'] ?? 1800;

        return $this->cache->remember($cacheKey, $ttl, function () use ($userId) {
            return $this->fetchUserRoles($userId);
        });
    }

    /**
     * Check if user has a specific permission.
     */
    public function userHasPermission(string $userId, string $permission, ?string $organizationId = null): bool
    {
        try {
            $permissions = $this->getUserPermissions($userId);
            
            // Direct permission check
            if (in_array($permission, $permissions)) {
                return true;
            }

            // Organization-scoped permission check
            if ($organizationId && $this->config['permissions']['organization_scoped'] ?? true) {
                return $this->userHasOrganizationPermission($userId, $permission, $organizationId);
            }

            // Hierarchical permission check
            if ($this->config['permissions']['hierarchical_permissions'] ?? true) {
                return $this->userHasHierarchicalPermission($userId, $permission);
            }

            return false;
        } catch (Exception $e) {
            $this->logPermissionEvent('permission_check_failed', [
                'user_id' => $userId,
                'permission' => $permission,
                'organization_id' => $organizationId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Check if user has a specific role.
     */
    public function userHasRole(string $userId, string $role, ?string $organizationId = null): bool
    {
        try {
            $roles = $this->getUserRoles($userId);
            
            // Direct role check
            if (in_array($role, $roles)) {
                return true;
            }

            // Organization-scoped role check
            if ($organizationId) {
                return $this->userHasOrganizationRole($userId, $role, $organizationId);
            }

            // Role inheritance check
            if ($this->config['permissions']['role_inheritance'] ?? true) {
                return $this->userHasInheritedRole($userId, $role);
            }

            return false;
        } catch (Exception $e) {
            $this->logPermissionEvent('role_check_failed', [
                'user_id' => $userId,
                'role' => $role,
                'organization_id' => $organizationId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Check if user has any of the specified permissions.
     */
    public function userHasAnyPermission(string $userId, array $permissions, ?string $organizationId = null): bool
    {
        foreach ($permissions as $permission) {
            if ($this->userHasPermission($userId, $permission, $organizationId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified permissions.
     */
    public function userHasAllPermissions(string $userId, array $permissions, ?string $organizationId = null): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->userHasPermission($userId, $permission, $organizationId)) {
                return false;
            }
        }

        return !empty($permissions);
    }

    /**
     * Get organization-specific permissions for a user.
     */
    public function getOrganizationPermissions(string $userId, string $organizationId, bool $useCache = true): array
    {
        if (!$useCache || !$this->cache) {
            return $this->fetchOrganizationPermissions($userId, $organizationId);
        }

        $cacheKey = $this->getCacheKey('org_permissions', "{$userId}:{$organizationId}");
        $ttl = $this->config['cache']['ttl']['permissions'] ?? 1800;

        return $this->cache->remember($cacheKey, $ttl, function () use ($userId, $organizationId) {
            return $this->fetchOrganizationPermissions($userId, $organizationId);
        });
    }

    /**
     * Get organization-specific roles for a user.
     */
    public function getOrganizationRoles(string $userId, string $organizationId, bool $useCache = true): array
    {
        if (!$useCache || !$this->cache) {
            return $this->fetchOrganizationRoles($userId, $organizationId);
        }

        $cacheKey = $this->getCacheKey('org_roles', "{$userId}:{$organizationId}");
        $ttl = $this->config['cache']['ttl']['permissions'] ?? 1800;

        return $this->cache->remember($cacheKey, $ttl, function () use ($userId, $organizationId) {
            return $this->fetchOrganizationRoles($userId, $organizationId);
        });
    }

    /**
     * Get all organizations where user has a specific permission.
     */
    public function getOrganizationsWithPermission(string $userId, string $permission): array
    {
        try {
            return $this->workos->executeWithRetry(function () use ($userId, $permission) {
                // This would use WorkOS API to find organizations where user has permission
                // Implementation depends on WorkOS API capabilities
                $user = $this->workos->getUser($userId);
                $organizations = [];

                if (isset($user['organization_memberships'])) {
                    foreach ($user['organization_memberships'] as $membership) {
                        $orgId = $membership['organization']['id'];
                        if ($this->userHasOrganizationPermission($userId, $permission, $orgId)) {
                            $organizations[] = $membership['organization'];
                        }
                    }
                }

                return $organizations;
            }, 'get_organizations_with_permission');
        } catch (Exception $e) {
            $this->logPermissionEvent('organization_permission_lookup_failed', [
                'user_id' => $userId,
                'permission' => $permission,
                'error' => $e->getMessage(),
            ]);

            return [];
        }
    }

    /**
     * Clear permissions cache for a user.
     */
    public function clearUserPermissionsCache(string $userId): void
    {
        if (!$this->cache) {
            return;
        }

        $keys = [
            $this->getCacheKey('user_permissions', $userId),
            $this->getCacheKey('user_roles', $userId),
        ];

        foreach ($keys as $key) {
            $this->cache->forget($key);
        }

        $this->logPermissionEvent('permissions_cache_cleared', [
            'user_id' => $userId,
        ]);
    }

    /**
     * Clear organization permissions cache for a user.
     */
    public function clearOrganizationPermissionsCache(string $userId, string $organizationId): void
    {
        if (!$this->cache) {
            return;
        }

        $keys = [
            $this->getCacheKey('org_permissions', "{$userId}:{$organizationId}"),
            $this->getCacheKey('org_roles', "{$userId}:{$organizationId}"),
        ];

        foreach ($keys as $key) {
            $this->cache->forget($key);
        }

        $this->logPermissionEvent('organization_permissions_cache_cleared', [
            'user_id' => $userId,
            'organization_id' => $organizationId,
        ]);
    }

    /**
     * Fetch user permissions from WorkOS API.
     */
    protected function fetchUserPermissions(string $userId): array
    {
        return $this->workos->executeWithRetry(function () use ($userId) {
            $user = $this->workos->getUser($userId);
            
            $permissions = [];
            
            // Extract direct permissions
            if (isset($user['permissions'])) {
                $permissions = array_merge($permissions, $user['permissions']);
            }

            // Extract permissions from organization memberships
            if (isset($user['organization_memberships'])) {
                foreach ($user['organization_memberships'] as $membership) {
                    if (isset($membership['permissions'])) {
                        $permissions = array_merge($permissions, $membership['permissions']);
                    }
                }
            }

            return array_unique($permissions);
        }, 'fetch_user_permissions');
    }

    /**
     * Fetch user roles from WorkOS API.
     */
    protected function fetchUserRoles(string $userId): array
    {
        return $this->workos->executeWithRetry(function () use ($userId) {
            $user = $this->workos->getUser($userId);
            
            $roles = [];
            
            // Extract direct roles
            if (isset($user['roles'])) {
                $roles = array_merge($roles, $user['roles']);
            }

            // Extract roles from organization memberships
            if (isset($user['organization_memberships'])) {
                foreach ($user['organization_memberships'] as $membership) {
                    if (isset($membership['role']['slug'])) {
                        $roles[] = $membership['role']['slug'];
                    } elseif (isset($membership['role']) && is_string($membership['role'])) {
                        $roles[] = $membership['role'];
                    }
                }
            }

            return array_unique($roles);
        }, 'fetch_user_roles');
    }

    /**
     * Fetch organization-specific permissions for a user.
     */
    protected function fetchOrganizationPermissions(string $userId, string $organizationId): array
    {
        return $this->workos->executeWithRetry(function () use ($userId, $organizationId) {
            $user = $this->workos->getUser($userId);
            
            if (!isset($user['organization_memberships'])) {
                return [];
            }

            foreach ($user['organization_memberships'] as $membership) {
                if ($membership['organization']['id'] === $organizationId) {
                    return $membership['permissions'] ?? [];
                }
            }

            return [];
        }, 'fetch_organization_permissions');
    }

    /**
     * Fetch organization-specific roles for a user.
     */
    protected function fetchOrganizationRoles(string $userId, string $organizationId): array
    {
        return $this->workos->executeWithRetry(function () use ($userId, $organizationId) {
            $user = $this->workos->getUser($userId);
            
            if (!isset($user['organization_memberships'])) {
                return [];
            }

            foreach ($user['organization_memberships'] as $membership) {
                if ($membership['organization']['id'] === $organizationId) {
                    $role = $membership['role'] ?? null;
                    if (is_string($role)) {
                        return [$role];
                    } elseif (is_array($role) && isset($role['slug'])) {
                        return [$role['slug']];
                    }
                }
            }

            return [];
        }, 'fetch_organization_roles');
    }

    /**
     * Check if user has organization-specific permission.
     */
    protected function userHasOrganizationPermission(string $userId, string $permission, string $organizationId): bool
    {
        $orgPermissions = $this->getOrganizationPermissions($userId, $organizationId);
        return in_array($permission, $orgPermissions);
    }

    /**
     * Check if user has organization-specific role.
     */
    protected function userHasOrganizationRole(string $userId, string $role, string $organizationId): bool
    {
        $orgRoles = $this->getOrganizationRoles($userId, $organizationId);
        return in_array($role, $orgRoles);
    }

    /**
     * Check if user has hierarchical permission (e.g., admin has all permissions).
     */
    protected function userHasHierarchicalPermission(string $userId, string $permission): bool
    {
        $roles = $this->getUserRoles($userId);
        
        // Define role hierarchy
        $hierarchy = [
            'admin' => ['*'], // Admin has all permissions
            'manager' => ['read', 'write', 'manage-team'],
            'member' => ['read'],
        ];

        foreach ($roles as $role) {
            if (isset($hierarchy[$role])) {
                $rolePermissions = $hierarchy[$role];
                if (in_array('*', $rolePermissions) || in_array($permission, $rolePermissions)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has inherited role.
     */
    protected function userHasInheritedRole(string $userId, string $targetRole): bool
    {
        $userRoles = $this->getUserRoles($userId);
        
        // Define role inheritance
        $inheritance = [
            'admin' => ['manager', 'member'],
            'manager' => ['member'],
        ];

        foreach ($userRoles as $role) {
            if ($role === $targetRole) {
                return true;
            }
            
            if (isset($inheritance[$role]) && in_array($targetRole, $inheritance[$role])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate cache key for permissions.
     */
    protected function getCacheKey(string $type, string $identifier): string
    {
        $prefix = $this->config['cache']['prefix'] ?? 'workos';
        return "{$prefix}:{$type}:{$identifier}";
    }

    /**
     * Log permission events for debugging and monitoring.
     */
    protected function logPermissionEvent(string $event, array $context = []): void
    {
        if (!($this->config['logging']['events']['authentication'] ?? true)) {
            return;
        }

        $logContext = array_merge([
            'event' => $event,
            'timestamp' => time(),
        ], $context);

        logger()->info("WorkOS Permissions: {$event}", $logContext);
    }
}