<?php

declare(strict_types=1);

namespace LaravelWorkOS\Services;

use Exception;
use Illuminate\Cache\CacheManager;
use Illuminate\Log\LogManager;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use WorkOS\AuditLogs;
use WorkOS\DirectorySync;
use WorkOS\Organizations;
use WorkOS\Passwordless;
use WorkOS\Portal;
use WorkOS\SSO;
use WorkOS\UserManagement;
use WorkOS\Webhook;
use WorkOS\WorkOS;

class WorkOSService
{
    protected array $config;
    protected ?LoggerInterface $logger;
    protected ?CacheManager $cache;
    protected int $retryAttempts;
    protected int $retryDelay;
    protected bool $circuitBreakerEnabled;
    protected array $circuitBreakerState = [];
    
    protected UserManagement $userManagement;
    protected Organizations $organizations;
    protected SSO $sso;
    protected DirectorySync $directorySync;
    protected AuditLogs $auditLogs;
    protected Portal $portal;
    protected Webhook $webhook;
    protected Passwordless $passwordless;

    public function __construct(
        array $config,
        ?LoggerInterface $logger = null,
        ?CacheManager $cache = null
    ) {
        $this->config = $config;
        $this->logger = $logger;
        $this->cache = $cache;
        
        $this->retryAttempts = $config['api']['retry_attempts'] ?? 3;
        $this->retryDelay = $config['api']['retry_delay'] ?? 1000;
        $this->circuitBreakerEnabled = $config['rate_limiting']['circuit_breaker']['enabled'] ?? true;
        
        // Set WorkOS credentials globally
        WorkOS::setApiKey($config['api_key']);
        WorkOS::setClientId($config['client_id']);
        
        // Instantiate services directly
        $this->userManagement = new UserManagement();
        $this->organizations = new Organizations();
        $this->sso = new SSO();
        $this->directorySync = new DirectorySync();
        $this->auditLogs = new AuditLogs();
        $this->portal = new Portal();
        $this->webhook = new Webhook();
        $this->passwordless = new Passwordless();
    }

    /**
     * Get the UserManagement service.
     */
    public function getUserManagement(): UserManagement
    {
        return $this->userManagement;
    }

    /**
     * Get the Organizations service.
     */
    public function getOrganizations(): Organizations
    {
        return $this->organizations;
    }

    /**
     * Get the SSO service.
     */
    public function getSSO(): SSO
    {
        return $this->sso;
    }

    /**
     * Get the DirectorySync service.
     */
    public function getDirectorySync(): DirectorySync
    {
        return $this->directorySync;
    }

    /**
     * Get the AuditLogs service.
     */
    public function getAuditLogs(): AuditLogs
    {
        return $this->auditLogs;
    }

    /**
     * Get the Portal service.
     */
    public function getPortal(): Portal
    {
        return $this->portal;
    }

    /**
     * Get the Webhook service.
     */
    public function getWebhook(): Webhook
    {
        return $this->webhook;
    }

    /**
     * Get the Passwordless service.
     */
    public function getPasswordless(): Passwordless
    {
        return $this->passwordless;
    }

    /**
     * Execute an API call with retry logic and error handling.
     */
    public function executeWithRetry(callable $callback, string $operation = 'unknown'): mixed
    {
        if ($this->circuitBreakerEnabled && $this->isCircuitBreakerOpen($operation)) {
            throw new RuntimeException("Circuit breaker is open for operation: {$operation}");
        }

        $lastException = null;
        $attempts = 0;

        while ($attempts < $this->retryAttempts) {
            try {
                $result = $callback();
                
                // Reset circuit breaker on success
                if ($this->circuitBreakerEnabled) {
                    $this->resetCircuitBreaker($operation);
                }
                
                $this->logApiCall($operation, 'success', $attempts + 1);
                
                return $result;
            } catch (Exception $e) {
                $lastException = $e;
                $attempts++;
                
                $this->logApiCall($operation, 'error', $attempts, $e->getMessage());
                
                // Check if we should retry
                if (!$this->shouldRetry($e, $attempts)) {
                    break;
                }
                
                // Wait before retrying
                if ($attempts < $this->retryAttempts) {
                    $this->waitBeforeRetry($attempts);
                }
            }
        }

        // Record failure in circuit breaker
        if ($this->circuitBreakerEnabled) {
            $this->recordCircuitBreakerFailure($operation);
        }

        throw new RuntimeException(
            "API call failed after {$attempts} attempts for operation: {$operation}",
            0,
            $lastException
        );
    }

    /**
     * Get a user by ID with caching.
     */
    public function getUser(string $userId, bool $useCache = true): ?array
    {
        if (!$useCache || !$this->cache) {
            return $this->executeWithRetry(
                fn() => $this->getUserManagement()->getUser($userId),
                'get_user'
            );
        }

        $cacheKey = $this->getCacheKey('user', $userId);
        $ttl = $this->config['cache']['ttl']['user'] ?? 3600;

        return $this->cache->remember($cacheKey, $ttl, function () use ($userId) {
            return $this->executeWithRetry(
                fn() => $this->getUserManagement()->getUser($userId),
                'get_user'
            );
        });
    }

    /**
     * List users with optional caching.
     */
    public function listUsers(
        ?string $email = null,
        ?string $organizationId = null,
        int $limit = 10,
        ?string $before = null,
        ?string $after = null,
        bool $useCache = false
    ): array {
        $callback = fn() => $this->getUserManagement()->listUsers(
            $email,
            $organizationId,
            $limit,
            $before,
            $after
        );

        if (!$useCache || !$this->cache) {
            return $this->executeWithRetry($callback, 'list_users');
        }

        $cacheKey = $this->getCacheKey('users', compact('email', 'organizationId', 'limit', 'before', 'after'));
        $ttl = $this->config['cache']['ttl']['user'] ?? 3600;

        return $this->cache->remember($cacheKey, $ttl, function () use ($callback) {
            return $this->executeWithRetry($callback, 'list_users');
        });
    }

    /**
     * Get an organization by ID with caching.
     */
    public function getOrganization(string $organizationId, bool $useCache = true): ?array
    {
        if (!$useCache || !$this->cache) {
            return $this->executeWithRetry(
                fn() => $this->getOrganizations()->getOrganization($organizationId),
                'get_organization'
            );
        }

        $cacheKey = $this->getCacheKey('organization', $organizationId);
        $ttl = $this->config['cache']['ttl']['organizations'] ?? 7200;

        return $this->cache->remember($cacheKey, $ttl, function () use ($organizationId) {
            return $this->executeWithRetry(
                fn() => $this->getOrganizations()->getOrganization($organizationId),
                'get_organization'
            );
        });
    }

    /**
     * List organizations with optional caching.
     */
    public function listOrganizations(
        ?array $domains = null,
        int $limit = 10,
        ?string $before = null,
        ?string $after = null,
        bool $useCache = false
    ): array {
        $callback = fn() => $this->getOrganizations()->listOrganizations(
            $domains,
            $limit,
            $before,
            $after
        );

        if (!$useCache || !$this->cache) {
            return $this->executeWithRetry($callback, 'list_organizations');
        }

        $cacheKey = $this->getCacheKey('organizations', compact('domains', 'limit', 'before', 'after'));
        $ttl = $this->config['cache']['ttl']['organizations'] ?? 7200;

        return $this->cache->remember($cacheKey, $ttl, function () use ($callback) {
            return $this->executeWithRetry($callback, 'list_organizations');
        });
    }

    /**
     * Get organization membership for a specific user.
     */
    public function getOrganizationMembership(string $organizationMembershipId, bool $useCache = true): ?array
    {
        if (!$useCache || !$this->cache) {
            return $this->executeWithRetry(
                fn() => $this->getUserManagement()->getOrganizationMembership($organizationMembershipId),
                'get_organization_membership'
            );
        }

        $cacheKey = $this->getCacheKey('organization_membership', $organizationMembershipId);
        $ttl = $this->config['cache']['ttl']['organizations'] ?? 7200;

        return $this->cache->remember($cacheKey, $ttl, function () use ($organizationMembershipId) {
            return $this->executeWithRetry(
                fn() => $this->getUserManagement()->getOrganizationMembership($organizationMembershipId),
                'get_organization_membership'
            );
        });
    }

    /**
     * Clear cache for a specific resource.
     */
    public function clearCache(string $type, string $identifier = null): void
    {
        if (!$this->cache) {
            return;
        }

        if ($identifier) {
            $cacheKey = $this->getCacheKey($type, $identifier);
            $this->cache->forget($cacheKey);
        } else {
            $pattern = $this->getCacheKey($type, '*');
            $this->cache->flush(); // Note: This is a simplified implementation
        }
    }

    /**
     * Clear all WorkOS cache.
     */
    public function clearAllCache(): void
    {
        if (!$this->cache) {
            return;
        }

        // This is a simplified implementation - in production you might want
        // to use cache tags or a more sophisticated approach
        $this->cache->flush();
    }

    /**
     * Check if the circuit breaker is open for a specific operation.
     */
    protected function isCircuitBreakerOpen(string $operation): bool
    {
        if (!isset($this->circuitBreakerState[$operation])) {
            return false;
        }

        $state = $this->circuitBreakerState[$operation];
        $threshold = $this->config['rate_limiting']['circuit_breaker']['failure_threshold'] ?? 5;
        $recovery = $this->config['rate_limiting']['circuit_breaker']['recovery_timeout'] ?? 60;

        // Check if we're in recovery period
        if ($state['failures'] >= $threshold) {
            if (time() - $state['last_failure'] < $recovery) {
                return true;
            }
            
            // Reset circuit breaker after recovery period
            $this->resetCircuitBreaker($operation);
        }

        return false;
    }

    /**
     * Record a failure in the circuit breaker.
     */
    protected function recordCircuitBreakerFailure(string $operation): void
    {
        if (!isset($this->circuitBreakerState[$operation])) {
            $this->circuitBreakerState[$operation] = ['failures' => 0, 'last_failure' => 0];
        }

        $this->circuitBreakerState[$operation]['failures']++;
        $this->circuitBreakerState[$operation]['last_failure'] = time();
    }

    /**
     * Reset the circuit breaker for a specific operation.
     */
    protected function resetCircuitBreaker(string $operation): void
    {
        unset($this->circuitBreakerState[$operation]);
    }

    /**
     * Determine if we should retry based on the exception and attempt count.
     */
    protected function shouldRetry(Exception $exception, int $attempts): bool
    {
        if ($attempts >= $this->retryAttempts) {
            return false;
        }

        // Don't retry on certain types of errors
        $nonRetryableErrors = [
            'authentication',
            'authorization', 
            'invalid_request',
            'not_found',
        ];

        $message = strtolower($exception->getMessage());
        foreach ($nonRetryableErrors as $error) {
            if (str_contains($message, $error)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Wait before retrying with exponential backoff.
     */
    protected function waitBeforeRetry(int $attempt): void
    {
        $delay = $this->retryDelay * (2 ** ($attempt - 1)); // Exponential backoff
        usleep($delay * 1000); // Convert to microseconds
    }

    /**
     * Log API call information.
     */
    protected function logApiCall(string $operation, string $status, int $attempts, ?string $error = null): void
    {
        if (!$this->logger || !($this->config['logging']['events']['api_calls'] ?? false)) {
            return;
        }

        $context = [
            'operation' => $operation,
            'status' => $status,
            'attempts' => $attempts,
        ];

        if ($error) {
            $context['error'] = $error;
        }

        if ($status === 'success') {
            $this->logger->info('WorkOS API call successful', $context);
        } else {
            $this->logger->error('WorkOS API call failed', $context);
        }
    }

    /**
     * Generate a cache key for the given type and identifier.
     */
    protected function getCacheKey(string $type, mixed $identifier): string
    {
        $prefix = $this->config['cache']['prefix'] ?? 'workos';
        
        if (is_array($identifier)) {
            $identifier = md5(serialize($identifier));
        }
        
        return "{$prefix}:{$type}:{$identifier}";
    }

    /**
     * Validate the configuration.
     */
    public function validateConfiguration(): array
    {
        $errors = [];

        if (empty($this->config['api_key'])) {
            $errors[] = 'WorkOS API key is required';
        }

        if (empty($this->config['client_id'])) {
            $errors[] = 'WorkOS client ID is required';
        }

        if (empty($this->config['cookie_password'])) {
            $errors[] = 'WorkOS cookie password is required';
        } elseif (strlen($this->config['cookie_password']) !== 32) {
            $errors[] = 'WorkOS cookie password must be exactly 32 characters';
        }

        return $errors;
    }

    /**
     * Test the connection to WorkOS API.
     */
    public function testConnection(): array
    {
        try {
            $start = microtime(true);
            
            // Try to get the current user to test the connection
            $user = $this->executeWithRetry(
                fn() => $this->getUserManagement()->listUsers(null, null, 1),
                'test_connection'
            );
            
            $duration = round((microtime(true) - $start) * 1000, 2);
            
            return [
                'success' => true,
                'duration_ms' => $duration,
                'message' => 'Connection successful',
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'message' => 'Connection failed',
            ];
        }
    }
}