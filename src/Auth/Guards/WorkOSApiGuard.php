<?php

declare(strict_types=1);

namespace LaravelWorkOS\Auth\Guards;

use Exception;
use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use LaravelWorkOS\Auth\Providers\WorkOSUserProvider;
use LaravelWorkOS\Services\WorkOSService;

class WorkOSApiGuard implements Guard
{
    protected Request $request;
    protected UserProvider $provider;
    protected WorkOSService $workos;
    protected array $config;
    protected ?CacheManager $cache;
    protected ?Authenticatable $user = null;
    protected bool $loggedOut = false;
    protected array $rateLimitingState = [];

    public function __construct(
        UserProvider $provider,
        Request $request,
        WorkOSService $workos,
        array $config,
        ?CacheManager $cache = null
    ) {
        $this->provider = $provider;
        $this->request = $request;
        $this->workos = $workos;
        $this->config = $config;
        $this->cache = $cache;
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
     * Get the currently authenticated user with enhanced security and caching.
     */
    public function user(): ?Authenticatable
    {
        if ($this->loggedOut) {
            return null;
        }

        if (!is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getTokenFromRequest();
        
        if (!$token) {
            return null;
        }

        // Check rate limiting
        if ($this->isRateLimited()) {
            $this->logSecurityEvent('rate_limit_exceeded', [
                'ip_address' => $this->request->ip(),
                'user_agent' => $this->request->userAgent(),
            ]);
            return null;
        }

        try {
            // Try to get user from token cache first
            if ($this->cache && ($this->config['cache']['enabled'] ?? true)) {
                $cachedUser = $this->getCachedTokenValidation($token);
                if ($cachedUser) {
                    $this->user = $cachedUser;
                    $this->recordSuccessfulAuthentication();
                    return $this->user;
                }
            }

            // Validate the token and get user
            if ($this->provider instanceof WorkOSUserProvider) {
                $this->user = $this->provider->validateToken($token);
                
                if ($this->user) {
                    // Cache the successful token validation
                    $this->cacheTokenValidation($token, $this->user);
                    $this->recordSuccessfulAuthentication();
                    
                    $this->logSecurityEvent('authentication_success', [
                        'user_id' => $this->user->getWorkOSId(),
                        'token_preview' => substr($token, 0, 20) . '...',
                    ]);
                } else {
                    $this->recordFailedAuthentication();
                    
                    $this->logSecurityEvent('authentication_failed', [
                        'reason' => 'invalid_token',
                        'token_preview' => substr($token, 0, 20) . '...',
                    ]);
                }
            }
        } catch (Exception $e) {
            $this->recordFailedAuthentication();
            
            Log::error('WorkOS API Guard: Failed to validate token', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 20) . '...',
                'ip_address' => $this->request->ip(),
                'user_agent' => $this->request->userAgent(),
            ]);

            $this->logSecurityEvent('authentication_error', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 20) . '...',
            ]);
        }

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
     * Validate a user's credentials with enhanced security.
     */
    public function validate(array $credentials = []): bool
    {
        if (empty($credentials['token'])) {
            return false;
        }

        // Check rate limiting
        if ($this->isRateLimited()) {
            return false;
        }

        try {
            if ($this->provider instanceof WorkOSUserProvider) {
                $user = $this->provider->validateToken($credentials['token']);
                $isValid = !is_null($user);
                
                if ($isValid) {
                    $this->recordSuccessfulAuthentication();
                } else {
                    $this->recordFailedAuthentication();
                }
                
                return $isValid;
            }
        } catch (Exception $e) {
            $this->recordFailedAuthentication();
            
            Log::error('WorkOS API Guard: Failed to validate credentials', [
                'error' => $e->getMessage(),
            ]);
        }

        return false;
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
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        if ($this->user) {
            $this->logSecurityEvent('user_logout', [
                'user_id' => $this->user->getAuthIdentifier(),
            ]);
        }

        $this->user = null;
        $this->loggedOut = true;
    }

    /**
     * Get the token from the request with enhanced extraction methods.
     */
    protected function getTokenFromRequest(): ?string
    {
        // Check Authorization header (Bearer token)
        $header = $this->request->header('Authorization');
        
        if ($header && str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        // Check for token in different header formats
        if ($header && str_starts_with($header, 'Token ')) {
            return substr($header, 6);
        }

        // Check custom header
        $customHeader = $this->request->header('X-WorkOS-Token');
        if ($customHeader) {
            return $customHeader;
        }

        // Check query parameter as fallback (less secure)
        $queryToken = $this->request->query('token');
        if ($queryToken) {
            $this->logSecurityEvent('token_from_query_parameter', [
                'warning' => 'Token passed via query parameter is less secure',
            ]);
            return $queryToken;
        }

        return null;
    }

    /**
     * Attempt to authenticate using WorkOS token with enhanced security.
     */
    public function attempt(array $credentials = []): bool
    {
        if (!isset($credentials['token'])) {
            return false;
        }

        // Check rate limiting
        if ($this->isRateLimited()) {
            return false;
        }

        try {
            if ($this->provider instanceof WorkOSUserProvider) {
                $user = $this->provider->validateToken($credentials['token']);
                
                if ($user) {
                    $this->setUser($user);
                    $this->recordSuccessfulAuthentication();
                    
                    $this->logSecurityEvent('manual_authentication_success', [
                        'user_id' => $user->getWorkOSId(),
                    ]);
                    
                    return true;
                } else {
                    $this->recordFailedAuthentication();
                }
            }
        } catch (Exception $e) {
            $this->recordFailedAuthentication();
            
            Log::error('WorkOS API Guard: Authentication attempt failed', [
                'error' => $e->getMessage(),
            ]);
        }

        return false;
    }

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool
    {
        return $this->attempt($credentials);
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
    public function onceUsingId($id): ?Authenticatable
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);
            return $user;
        }

        return null;
    }

    /**
     * Log a user into the application.
     */
    public function login(Authenticatable $user, $remember = false): void
    {
        $this->setUser($user);
        
        $this->logSecurityEvent('user_login', [
            'user_id' => $user->getAuthIdentifier(),
            'remember' => $remember,
        ]);
    }

    /**
     * Log the given user ID into the application.
     */
    public function loginUsingId($id, $remember = false): ?Authenticatable
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->login($user, $remember);
            return $user;
        }

        return null;
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
     * Get the request instance.
     */
    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * Set the request instance.
     */
    public function setRequest(Request $request): void
    {
        $this->request = $request;
        $this->user = null;
        $this->loggedOut = false;
    }

    /**
     * Check if requests are being rate limited.
     */
    protected function isRateLimited(): bool
    {
        if (!($this->config['rate_limiting']['enabled'] ?? true)) {
            return false;
        }

        $key = $this->getRateLimitKey();
        $limit = $this->config['rate_limiting']['requests_per_minute'] ?? 60;
        $window = 60; // 1 minute

        if (!isset($this->rateLimitingState[$key])) {
            $this->rateLimitingState[$key] = ['count' => 0, 'reset_time' => time() + $window];
        }

        $state = $this->rateLimitingState[$key];

        // Reset counter if window has passed
        if (time() >= $state['reset_time']) {
            $this->rateLimitingState[$key] = ['count' => 1, 'reset_time' => time() + $window];
            return false;
        }

        // Check if limit exceeded
        if ($state['count'] >= $limit) {
            return true;
        }

        // Increment counter
        $this->rateLimitingState[$key]['count']++;
        return false;
    }

    /**
     * Get rate limiting key based on IP address.
     */
    protected function getRateLimitKey(): string
    {
        return 'workos_api_guard:' . $this->request->ip();
    }

    /**
     * Record successful authentication for rate limiting.
     */
    protected function recordSuccessfulAuthentication(): void
    {
        // Reset failed attempts on successful auth
        $key = $this->getRateLimitKey() . ':failed';
        unset($this->rateLimitingState[$key]);
    }

    /**
     * Record failed authentication for rate limiting.
     */
    protected function recordFailedAuthentication(): void
    {
        if (!($this->config['rate_limiting']['enabled'] ?? true)) {
            return;
        }

        $key = $this->getRateLimitKey() . ':failed';
        $maxFailures = $this->config['rate_limiting']['max_failures'] ?? 5;

        if (!isset($this->rateLimitingState[$key])) {
            $this->rateLimitingState[$key] = ['count' => 0, 'reset_time' => time() + 300]; // 5 minutes
        }

        $this->rateLimitingState[$key]['count']++;

        // Log suspicious activity
        if ($this->rateLimitingState[$key]['count'] >= $maxFailures) {
            $this->logSecurityEvent('suspicious_activity_detected', [
                'failed_attempts' => $this->rateLimitingState[$key]['count'],
                'ip_address' => $this->request->ip(),
                'user_agent' => $this->request->userAgent(),
            ]);
        }
    }

    /**
     * Get cached token validation result.
     */
    protected function getCachedTokenValidation(string $token): ?WorkOSUser
    {
        if (!$this->cache) {
            return null;
        }

        $cacheKey = $this->getTokenCacheKey($token);
        $userData = $this->cache->get($cacheKey);
        
        if ($userData && $this->provider instanceof WorkOSUserProvider) {
            return $this->provider->createWorkOSUser($userData);
        }

        return null;
    }

    /**
     * Cache successful token validation.
     */
    protected function cacheTokenValidation(string $token, WorkOSUser $user): void
    {
        if (!$this->cache || !($this->config['cache']['enabled'] ?? true)) {
            return;
        }

        $cacheKey = $this->getTokenCacheKey($token);
        $ttl = $this->config['cache']['ttl']['tokens'] ?? 300; // 5 minutes
        
        $this->cache->put($cacheKey, $user->getRawData(), $ttl);
    }

    /**
     * Generate cache key for token validation.
     */
    protected function getTokenCacheKey(string $token): string
    {
        $prefix = $this->config['cache']['prefix'] ?? 'workos';
        $tokenHash = hash('sha256', $token);
        return "{$prefix}:token_validation:{$tokenHash}";
    }

    /**
     * Log security events for monitoring.
     */
    protected function logSecurityEvent(string $event, array $context = []): void
    {
        if (!($this->config['logging']['events']['authentication'] ?? true)) {
            return;
        }

        $logContext = array_merge([
            'guard' => 'workos-api',
            'event' => $event,
            'timestamp' => time(),
            'ip_address' => $this->request->ip(),
            'user_agent' => $this->request->userAgent(),
            'request_id' => $this->request->header('X-Request-ID') ?: uniqid(),
        ], $context);

        Log::info("WorkOS API Guard Security Event: {$event}", $logContext);
    }

    /**
     * Clear token cache for security purposes.
     */
    public function clearTokenCache(): void
    {
        if (!$this->cache) {
            return;
        }

        // This is a simplified implementation
        // In production, you might want to use cache tags
        // or more sophisticated cache clearing
        $this->cache->flush();
    }

    /**
     * Get authentication statistics.
     */
    public function getAuthStats(): array
    {
        return [
            'authenticated' => $this->check(),
            'user_id' => $this->id(),
            'rate_limited' => $this->isRateLimited(),
            'cache_enabled' => $this->cache && ($this->config['cache']['enabled'] ?? true),
        ];
    }
}