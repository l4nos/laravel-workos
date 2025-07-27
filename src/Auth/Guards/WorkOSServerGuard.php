<?php

declare(strict_types=1);

namespace LaravelWorkOS\Auth\Guards;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Log;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use LaravelWorkOS\Services\WorkOSService;
use RuntimeException;

class WorkOSServerGuard implements Guard
{
    protected UserProvider $provider;
    protected WorkOSService $workos;
    protected array $config;
    protected ?Authenticatable $user = null;
    protected bool $loggedOut = false;
    protected ?string $impersonatedUserId = null;
    protected string $name;

    public function __construct(
        UserProvider $provider,
        WorkOSService $workos,
        array $config,
        string $name = 'workos-server'
    ) {
        $this->provider = $provider;
        $this->workos = $workos;
        $this->config = $config;
        $this->name = $name;
    }

    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Get the currently authenticated user (or impersonated user).
     */
    public function user(): ?Authenticatable
    {
        if ($this->loggedOut) {
            return null;
        }

        if (!is_null($this->user)) {
            return $this->user;
        }

        // For server guard, authentication is based on valid API configuration
        if (!$this->isValidServerAuth()) {
            return null;
        }

        // If impersonating a user, return that user
        if ($this->impersonatedUserId) {
            try {
                $this->user = $this->provider->retrieveById($this->impersonatedUserId);
                
                if ($this->user) {
                    $this->logServerEvent('user_impersonated', [
                        'impersonated_user_id' => $this->impersonatedUserId,
                    ]);
                }
                
                return $this->user;
            } catch (Exception $e) {
                Log::error('WorkOS Server Guard: Failed to impersonate user', [
                    'user_id' => $this->impersonatedUserId,
                    'error' => $e->getMessage(),
                ]);
                
                $this->impersonatedUserId = null;
                return null;
            }
        }

        // For server context, create a system user
        $this->user = $this->createSystemUser();
        
        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): mixed
    {
        if ($user = $this->user()) {
            return $user->getAuthIdentifier();
        }

        return null;
    }

    /**
     * Determine if the guard has a user instance.
     */
    public function hasUser(): bool
    {
        return !is_null($this->user);
    }

    /**
     * Validate server credentials.
     */
    public function validate(array $credentials = []): bool
    {
        // For server guard, validation is based on API key presence and validity
        return $this->isValidServerAuth();
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool
    {
        return false;
    }

    /**
     * Set the current user.
     */
    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;
        $this->loggedOut = false;
        
        $this->logServerEvent('user_set', [
            'user_id' => $user->getAuthIdentifier(),
        ]);
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        if ($this->user) {
            $this->logServerEvent('user_logout', [
                'user_id' => $this->user->getAuthIdentifier(),
                'was_impersonating' => $this->impersonatedUserId !== null,
            ]);
        }

        $this->user = null;
        $this->impersonatedUserId = null;
        $this->loggedOut = true;
    }

    /**
     * Impersonate a specific user for administrative operations.
     */
    public function impersonate(string $userId): bool
    {
        try {
            // Verify the user exists
            $user = $this->provider->retrieveById($userId);
            
            if (!$user) {
                $this->logServerEvent('impersonation_failed', [
                    'target_user_id' => $userId,
                    'reason' => 'user_not_found',
                ]);
                return false;
            }

            $this->impersonatedUserId = $userId;
            $this->user = null; // Force reload on next access
            
            $this->logServerEvent('impersonation_started', [
                'target_user_id' => $userId,
            ]);
            
            return true;
        } catch (Exception $e) {
            Log::error('WorkOS Server Guard: Failed to impersonate user', [
                'target_user_id' => $userId,
                'error' => $e->getMessage(),
            ]);
            
            return false;
        }
    }

    /**
     * Stop impersonating and return to server context.
     */
    public function stopImpersonating(): void
    {
        if ($this->impersonatedUserId) {
            $this->logServerEvent('impersonation_stopped', [
                'was_impersonating_user_id' => $this->impersonatedUserId,
            ]);
            
            $this->impersonatedUserId = null;
            $this->user = null; // Force reload to system user
        }
    }

    /**
     * Check if currently impersonating a user.
     */
    public function isImpersonating(): bool
    {
        return $this->impersonatedUserId !== null;
    }

    /**
     * Get the ID of the user being impersonated.
     */
    public function getImpersonatedUserId(): ?string
    {
        return $this->impersonatedUserId;
    }

    /**
     * Perform bulk user operations with better error handling.
     */
    public function bulkUserOperation(callable $operation, array $userIds): array
    {
        $results = [];
        $errors = [];
        
        $this->logServerEvent('bulk_operation_started', [
            'user_count' => count($userIds),
        ]);

        foreach ($userIds as $userId) {
            try {
                if ($this->impersonate($userId)) {
                    $result = $operation($this->user());
                    $results[$userId] = $result;
                    $this->stopImpersonating();
                } else {
                    $errors[$userId] = 'Failed to impersonate user';
                }
            } catch (Exception $e) {
                $errors[$userId] = $e->getMessage();
                $this->stopImpersonating(); // Ensure we stop impersonating on error
            }
        }

        $this->logServerEvent('bulk_operation_completed', [
            'success_count' => count($results),
            'error_count' => count($errors),
        ]);

        return [
            'results' => $results,
            'errors' => $errors,
        ];
    }

    /**
     * Get all users from a specific organization.
     */
    public function getOrganizationUsers(string $organizationId, int $limit = 100): array
    {
        try {
            return $this->workos->listUsers(
                organizationId: $organizationId,
                limit: $limit,
                useCache: false
            );
        } catch (Exception $e) {
            Log::error('WorkOS Server Guard: Failed to get organization users', [
                'organization_id' => $organizationId,
                'error' => $e->getMessage(),
            ]);
            
            return [];
        }
    }

    /**
     * Create a user in WorkOS (administrative operation).
     */
    public function createUser(array $userData): ?WorkOSUser
    {
        try {
            // This would use WorkOS API to create a user
            // Implementation depends on WorkOS API capabilities
            $result = $this->workos->executeWithRetry(function () use ($userData) {
                return $this->workos->getUserManagement()->createUser($userData);
            }, 'create_user');

            if ($result) {
                // Cast provider to WorkOSUserProvider to access createWorkOSUser method
                if ($this->provider instanceof \LaravelWorkOS\Auth\Providers\WorkOSUserProvider) {
                    $user = $this->provider->createWorkOSUser($result);
                    
                    $this->logServerEvent('user_created', [
                        'created_user_id' => $user->getWorkOSId(),
                        'email' => $userData['email'] ?? null,
                    ]);
                    
                    return $user;
                }
            }
        } catch (Exception $e) {
            Log::error('WorkOS Server Guard: Failed to create user', [
                'user_data' => $userData,
                'error' => $e->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * Update user data (administrative operation).
     */
    public function updateUser(string $userId, array $updateData): bool
    {
        try {
            $result = $this->workos->executeWithRetry(function () use ($userId, $updateData) {
                return $this->workos->getUserManagement()->updateUser($userId, $updateData);
            }, 'update_user');

            if ($result) {
                $this->logServerEvent('user_updated', [
                    'updated_user_id' => $userId,
                    'fields' => array_keys($updateData),
                ]);
                
                return true;
            }
        } catch (Exception $e) {
            Log::error('WorkOS Server Guard: Failed to update user', [
                'user_id' => $userId,
                'update_data' => $updateData,
                'error' => $e->getMessage(),
            ]);
        }

        return false;
    }

    /**
     * Delete a user (administrative operation).
     */
    public function deleteUser(string $userId): bool
    {
        try {
            $result = $this->workos->executeWithRetry(function () use ($userId) {
                return $this->workos->getUserManagement()->deleteUser($userId);
            }, 'delete_user');

            if ($result) {
                $this->logServerEvent('user_deleted', [
                    'deleted_user_id' => $userId,
                ]);
                
                return true;
            }
        } catch (Exception $e) {
            Log::error('WorkOS Server Guard: Failed to delete user', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);
        }

        return false;
    }

    /**
     * Get server authentication statistics.
     */
    public function getServerStats(): array
    {
        return [
            'guard_name' => $this->name,
            'authenticated' => $this->check(),
            'impersonating' => $this->isImpersonating(),
            'impersonated_user_id' => $this->getImpersonatedUserId(),
            'api_configured' => $this->isValidServerAuth(),
            'system_user' => $this->user instanceof WorkOSUser && $this->user->getWorkOSId() === 'system',
        ];
    }

    /**
     * Test WorkOS API connectivity.
     */
    public function testConnection(): array
    {
        return $this->workos->testConnection();
    }

    /**
     * Get the user provider used by the guard.
     */
    public function getProvider(): UserProvider
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     */
    public function setProvider(UserProvider $provider): void
    {
        $this->provider = $provider;
    }

    /**
     * Get the WorkOS service instance.
     */
    public function getWorkOS(): WorkOSService
    {
        return $this->workos;
    }

    /**
     * Check if server authentication is valid.
     */
    protected function isValidServerAuth(): bool
    {
        // Check if API key and client ID are configured
        $apiKey = $this->config['api_key'] ?? null;
        $clientId = $this->config['client_id'] ?? null;

        if (!$apiKey || !$clientId) {
            return false;
        }

        // Basic format validation
        if (!str_starts_with($apiKey, 'sk_')) {
            return false;
        }

        if (!str_starts_with($clientId, 'client_')) {
            return false;
        }

        return true;
    }

    /**
     * Create a system user for server operations.
     */
    protected function createSystemUser(): WorkOSUser
    {
        $systemUserData = [
            'id' => 'system',
            'email' => 'system@workos.server',
            'first_name' => 'System',
            'last_name' => 'User',
            'email_verified' => true,
            'permissions' => ['*'], // System user has all permissions
            'roles' => ['system'],
            'active' => true,
            'organization_id' => null,
            'organizations' => [],
            'raw_data' => [
                'type' => 'server_guard_system_user',
                'created_at' => date('c'),
            ],
        ];

        return new WorkOSUser($systemUserData);
    }

    /**
     * Log server-related events.
     */
    protected function logServerEvent(string $event, array $context = []): void
    {
        if (!($this->config['logging']['events']['authentication'] ?? true)) {
            return;
        }

        $logContext = array_merge([
            'guard' => $this->name,
            'event' => $event,
            'timestamp' => time(),
            'context' => 'server_authentication',
        ], $context);

        Log::info("WorkOS Server Guard: {$event}", $logContext);
    }

    /**
     * Get the guard name.
     */
    public function getName(): string
    {
        return $this->name;
    }
}