<?php

declare(strict_types=1);

namespace LaravelWorkOS\Auth\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;

class WorkOSUser implements Authenticatable
{
    protected array $attributes = [];
    protected array $permissions = [];
    protected array $roles = [];
    protected array $organizations = [];
    protected ?string $currentOrganizationId = null;

    public function __construct(array $attributes = [])
    {
        $this->attributes = $attributes;
        $this->permissions = $attributes['permissions'] ?? [];
        $this->roles = $attributes['roles'] ?? [];
        $this->organizations = $attributes['organizations'] ?? [];
        $this->currentOrganizationId = $attributes['organization_id'] ?? null;
    }

    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): mixed
    {
        return $this->attributes['id'] ?? null;
    }

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string
    {
        return null;
    }

    /**
     * Get the name of the password field.
     */
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Get the token value for the "remember me" session.
     */
    public function getRememberToken(): ?string
    {
        return null;
    }

    /**
     * Set the token value for the "remember me" session.
     */
    public function setRememberToken($value): void
    {
        // Not implemented for WorkOS
    }

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string
    {
        return null;
    }

    /**
     * Get the user's WorkOS ID.
     */
    public function getWorkOSId(): ?string
    {
        return $this->attributes['id'] ?? null;
    }

    /**
     * Get the user's email.
     */
    public function getEmail(): ?string
    {
        return $this->attributes['email'] ?? null;
    }

    /**
     * Get the user's first name.
     */
    public function getFirstName(): ?string
    {
        return $this->attributes['first_name'] ?? null;
    }

    /**
     * Get the user's last name.
     */
    public function getLastName(): ?string
    {
        return $this->attributes['last_name'] ?? null;
    }

    /**
     * Get the user's full name.
     */
    public function getName(): ?string
    {
        $firstName = $this->getFirstName();
        $lastName = $this->getLastName();
        
        if ($firstName && $lastName) {
            return "{$firstName} {$lastName}";
        }
        
        return $firstName ?: $lastName ?: $this->getEmail();
    }

    /**
     * Get all user attributes.
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Get the raw WorkOS data.
     */
    public function getRawData(): array
    {
        return $this->attributes['raw_data'] ?? [];
    }

    /**
     * Get a specific attribute.
     */
    public function getAttribute(string $key): mixed
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Set a specific attribute.
     */
    public function setAttribute(string $key, mixed $value): void
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Get user permissions with organization context.
     */
    public function getPermissions(?string $organizationId = null): array
    {
        if ($organizationId) {
            return $this->getOrganizationPermissions($organizationId);
        }

        return $this->permissions;
    }

    /**
     * Check if user has a specific permission with organization context.
     */
    public function hasPermission(string $permission, ?string $organizationId = null): bool
    {
        $permissions = $this->getPermissions($organizationId);
        
        // Direct permission check
        if (in_array($permission, $permissions)) {
            return true;
        }

        // Check hierarchical permissions
        return $this->hasHierarchicalPermission($permission, $organizationId);
    }

    /**
     * Check if user has any of the specified permissions.
     */
    public function hasAnyPermission(array $permissions, ?string $organizationId = null): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission, $organizationId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified permissions.
     */
    public function hasAllPermissions(array $permissions, ?string $organizationId = null): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($permission, $organizationId)) {
                return false;
            }
        }

        return !empty($permissions);
    }

    /**
     * Get user roles with organization context.
     */
    public function getRoles(?string $organizationId = null): array
    {
        if ($organizationId) {
            return $this->getOrganizationRoles($organizationId);
        }

        return $this->roles;
    }

    /**
     * Check if user has a specific role with organization context.
     */
    public function hasRole(string $role, ?string $organizationId = null): bool
    {
        $roles = $this->getRoles($organizationId);
        
        // Direct role check
        if (in_array($role, $roles)) {
            return true;
        }

        // Check role inheritance
        return $this->hasInheritedRole($role, $organizationId);
    }

    /**
     * Check if user has any of the specified roles.
     */
    public function hasAnyRole(array $roles, ?string $organizationId = null): bool
    {
        foreach ($roles as $role) {
            if ($this->hasRole($role, $organizationId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the user's primary organization ID.
     */
    public function getOrganizationId(): ?string
    {
        return $this->currentOrganizationId ?: $this->attributes['organization_id'] ?? null;
    }

    /**
     * Get all organizations the user belongs to.
     */
    public function getOrganizations(): array
    {
        return $this->organizations;
    }

    /**
     * Get a specific organization by ID.
     */
    public function getOrganization(string $organizationId): ?array
    {
        foreach ($this->organizations as $org) {
            if ($org['id'] === $organizationId) {
                return $org;
            }
        }

        return null;
    }

    /**
     * Check if user belongs to a specific organization.
     */
    public function belongsToOrganization(string $organizationId): bool
    {
        return $this->getOrganization($organizationId) !== null;
    }

    /**
     * Get the user's active/current organization.
     */
    public function getActiveOrganization(): ?array
    {
        $activeOrgId = $this->getOrganizationId();
        return $activeOrgId ? $this->getOrganization($activeOrgId) : null;
    }

    /**
     * Switch to a different organization context.
     */
    public function switchOrganization(string $organizationId): bool
    {
        if (!$this->belongsToOrganization($organizationId)) {
            return false;
        }

        $this->currentOrganizationId = $organizationId;
        $this->attributes['organization_id'] = $organizationId;
        
        return true;
    }

    /**
     * Get organization-specific permissions.
     */
    public function getOrganizationPermissions(string $organizationId): array
    {
        $org = $this->getOrganization($organizationId);
        return $org['permissions'] ?? [];
    }

    /**
     * Get organization-specific roles.
     */
    public function getOrganizationRoles(string $organizationId): array
    {
        $org = $this->getOrganization($organizationId);
        $role = $org['role'] ?? null;
        return $role ? [$role] : [];
    }

    /**
     * Get the user's role in a specific organization.
     */
    public function getOrganizationRole(string $organizationId): ?string
    {
        $org = $this->getOrganization($organizationId);
        return $org['role'] ?? null;
    }

    /**
     * Check if the user is active.
     */
    public function isActive(): bool
    {
        return ($this->attributes['active'] ?? true) === true;
    }

    /**
     * Check if the user's email is verified.
     */
    public function isEmailVerified(): bool
    {
        return ($this->attributes['email_verified'] ?? false) === true;
    }

    /**
     * Get the user's profile picture URL.
     */
    public function getProfilePictureUrl(): ?string
    {
        return $this->attributes['profile_picture_url'] ?? null;
    }

    /**
     * Get available organizations that user can switch to.
     */
    public function getAvailableOrganizations(): array
    {
        return array_filter($this->organizations, function ($org) {
            return ($org['status'] ?? 'active') === 'active';
        });
    }

    /**
     * Check if user is admin in any organization.
     */
    public function isAdmin(?string $organizationId = null): bool
    {
        return $this->hasRole('admin', $organizationId);
    }

    /**
     * Check if user is manager in any organization.
     */
    public function isManager(?string $organizationId = null): bool
    {
        return $this->hasRole('manager', $organizationId);
    }

    /**
     * Check if user is owner of any organization.
     */
    public function isOwner(?string $organizationId = null): bool
    {
        return $this->hasRole('owner', $organizationId);
    }

    /**
     * Get user's highest role across all organizations.
     */
    public function getHighestRole(): ?string
    {
        $roleHierarchy = ['owner' => 4, 'admin' => 3, 'manager' => 2, 'member' => 1];
        $highestRole = null;
        $highestPriority = 0;

        foreach ($this->organizations as $org) {
            $role = $org['role'] ?? null;
            if ($role && isset($roleHierarchy[$role])) {
                $priority = $roleHierarchy[$role];
                if ($priority > $highestPriority) {
                    $highestPriority = $priority;
                    $highestRole = $role;
                }
            }
        }

        return $highestRole;
    }

    /**
     * Get creation timestamp.
     */
    public function getCreatedAt(): ?string
    {
        return $this->attributes['created_at'] ?? null;
    }

    /**
     * Get last update timestamp.
     */
    public function getUpdatedAt(): ?string
    {
        return $this->attributes['updated_at'] ?? null;
    }

    /**
     * Convert to array representation.
     */
    public function toArray(): array
    {
        return [
            'id' => $this->getWorkOSId(),
            'email' => $this->getEmail(),
            'first_name' => $this->getFirstName(),
            'last_name' => $this->getLastName(),
            'name' => $this->getName(),
            'email_verified' => $this->isEmailVerified(),
            'profile_picture_url' => $this->getProfilePictureUrl(),
            'organization_id' => $this->getOrganizationId(),
            'organizations' => $this->getOrganizations(),
            'permissions' => $this->getPermissions(),
            'roles' => $this->getRoles(),
            'active' => $this->isActive(),
            'created_at' => $this->getCreatedAt(),
            'updated_at' => $this->getUpdatedAt(),
        ];
    }

    /**
     * Convert to JSON representation with selective data inclusion.
     */
    public function toJson(array $options = []): string
    {
        $data = $this->toArray();
        
        // Remove sensitive data if requested
        if ($options['hide_sensitive'] ?? false) {
            unset($data['raw_data']);
        }
        
        // Include only specified fields if provided
        if (!empty($options['only'])) {
            $data = array_intersect_key($data, array_flip($options['only']));
        }
        
        // Exclude specified fields if provided
        if (!empty($options['except'])) {
            $data = array_diff_key($data, array_flip($options['except']));
        }
        
        return json_encode($data);
    }

    /**
     * Refresh permissions from the permission service.
     */
    public function refreshPermissions(): self
    {
        // This would typically interact with the permission service
        // to fetch fresh permissions from WorkOS
        if (function_exists('app')) {
            try {
                $permissionService = app('workos.permissions');
                $this->permissions = $permissionService->getUserPermissions($this->getWorkOSId(), false);
                $this->roles = $permissionService->getUserRoles($this->getWorkOSId(), false);
            } catch (\Exception $e) {
                // Log error but don't throw to avoid breaking the application
                if (function_exists('logger')) {
                    logger()->warning('Failed to refresh user permissions', [
                        'user_id' => $this->getWorkOSId(),
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        return $this;
    }

    /**
     * Check hierarchical permissions (e.g., admin has all permissions).
     */
    protected function hasHierarchicalPermission(string $permission, ?string $organizationId = null): bool
    {
        $roles = $this->getRoles($organizationId);
        
        // Define role hierarchy with permissions
        $rolePermissions = [
            'owner' => ['*'], // Owner has all permissions
            'admin' => ['*'], // Admin has all permissions
            'manager' => ['read', 'write', 'manage-team', 'manage-projects'],
            'member' => ['read', 'write'],
        ];

        foreach ($roles as $role) {
            if (isset($rolePermissions[$role])) {
                $permissions = $rolePermissions[$role];
                if (in_array('*', $permissions) || in_array($permission, $permissions)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check inherited roles (e.g., admin inherits manager permissions).
     */
    protected function hasInheritedRole(string $targetRole, ?string $organizationId = null): bool
    {
        $userRoles = $this->getRoles($organizationId);
        
        // Define role inheritance
        $roleInheritance = [
            'owner' => ['admin', 'manager', 'member'],
            'admin' => ['manager', 'member'],
            'manager' => ['member'],
        ];

        foreach ($userRoles as $role) {
            if ($role === $targetRole) {
                return true;
            }
            
            if (isset($roleInheritance[$role]) && in_array($targetRole, $roleInheritance[$role])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Magic getter for attributes.
     */
    public function __get(string $key): mixed
    {
        return $this->getAttribute($key);
    }

    /**
     * Magic setter for attributes.
     */
    public function __set(string $key, mixed $value): void
    {
        $this->setAttribute($key, $value);
    }

    /**
     * Magic isset for attributes.
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * String representation of the user.
     */
    public function __toString(): string
    {
        return $this->getName() ?: $this->getEmail() ?: $this->getWorkOSId() ?: 'WorkOS User';
    }
}