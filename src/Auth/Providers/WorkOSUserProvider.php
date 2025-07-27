<?php

declare(strict_types=1);

namespace LaravelWorkOS\Auth\Providers;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use LaravelWorkOS\Services\WorkOSService;
use RuntimeException;

class WorkOSUserProvider implements UserProvider
{
    protected WorkOSService $workos;
    protected array $config;
    protected ?CacheManager $cache;
    protected array $jwksCache = [];

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
     * Retrieve a user by their unique identifier.
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        try {
            $user = $this->workos->getUser($identifier, true);
            return $user ? $this->createWorkOSUser($user) : null;
        } catch (Exception $e) {
            Log::error('Failed to retrieve WorkOS user by ID', [
                'user_id' => $identifier,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return null;
        }
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByToken($identifier, $token): ?Authenticatable
    {
        // WorkOS doesn't use remember tokens
        return null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     */
    public function updateRememberToken(Authenticatable $user, $token): void
    {
        // WorkOS doesn't use remember tokens
    }

    /**
     * Retrieve a user by the given credentials.
     */
    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        // For WorkOS, we typically retrieve by token or session
        if (isset($credentials['workos_id'])) {
            return $this->retrieveById($credentials['workos_id']);
        }

        if (isset($credentials['email'])) {
            try {
                $users = $this->workos->listUsers(
                    email: $credentials['email'],
                    limit: 1,
                    useCache: false
                );

                if (!empty($users['data'])) {
                    return $this->createWorkOSUser($users['data'][0]);
                }
            } catch (Exception $e) {
                Log::error('Failed to retrieve WorkOS user by email', [
                    'email' => $credentials['email'],
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return null;
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        // WorkOS handles credential validation through tokens/sessions
        // This method is typically not used for token-based authentication
        return false;
    }

    /**
     * Rehash the user's password if required and supported.
     */
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void
    {
        // WorkOS handles password management
    }

    /**
     * Create a WorkOSUser instance from WorkOS user data with enhanced features.
     */
    public function createWorkOSUser($userData): WorkOSUser
    {
        // Convert WorkOS Resource object to array if needed
        if (is_object($userData) && method_exists($userData, 'toArray')) {
            $userData = $userData->toArray();
        } elseif (is_object($userData)) {
            // Convert object properties to array
            $userData = json_decode(json_encode($userData), true);
        }

        // Enhanced organization membership handling
        $organizations = $this->extractOrganizations($userData);
        $permissions = $this->extractPermissions($userData);
        $roles = $this->extractRoles($userData);

        // Map WorkOS user data to our WorkOSUser attributes with enhanced features
        $attributes = [
            'id' => $userData['id'] ?? null,
            'email' => $userData['email'] ?? null,
            'first_name' => $userData['first_name'] ?? null,
            'last_name' => $userData['last_name'] ?? null,
            'email_verified' => $userData['email_verified'] ?? false,
            'profile_picture_url' => $userData['profile_picture_url'] ?? null,
            'created_at' => $userData['created_at'] ?? null,
            'updated_at' => $userData['updated_at'] ?? null,
            'organization_id' => $this->extractPrimaryOrganizationId($userData),
            'organizations' => $organizations,
            'permissions' => $permissions,
            'roles' => $roles,
            'active' => true, // WorkOS users are active by default
            'raw_data' => $userData, // Store original data for reference
        ];

        return new WorkOSUser($attributes);
    }

    /**
     * Validate a WorkOS JWT token with proper signature verification.
     */
    public function validateToken(string $token): ?WorkOSUser
    {
        try {
            // Skip validation in development if configured
            if ($this->config['development']['bypass_signature_verification'] ?? false) {
                $payload = $this->decodeJwtTokenInsecure($token);
                if ($payload && isset($payload['sub'])) {
                    return $this->retrieveById($payload['sub']);
                }
                return null;
            }

            // Perform secure JWT validation
            $payload = $this->validateJwtToken($token);
            
            if ($payload && isset($payload['sub'])) {
                // Try to get user from cache first
                $user = $this->getUserFromCache($payload['sub']);
                if ($user) {
                    return $user;
                }

                // Fetch from WorkOS API and cache
                $user = $this->retrieveById($payload['sub']);
                if ($user) {
                    $this->cacheUser($user);
                }
                
                return $user;
            }

            return null;
        } catch (Exception $e) {
            Log::error('Failed to validate WorkOS token', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 20) . '...',
            ]);
            
            return null;
        }
    }

    /**
     * Validate JWT token with proper signature verification.
     */
    protected function validateJwtToken(string $token): ?array
    {
        if (!$this->config['jwt']['verify_signature'] ?? true) {
            return $this->decodeJwtTokenInsecure($token);
        }

        try {
            // Get JWKS (JSON Web Key Set) for signature verification
            $jwks = $this->getJwks();
            
            // Parse token header to get key ID
            $header = $this->parseJwtHeader($token);
            $keyId = $header['kid'] ?? null;
            
            if (!$keyId || !isset($jwks[$keyId])) {
                throw new InvalidArgumentException('Invalid or missing key ID in JWT header');
            }

            $publicKey = $jwks[$keyId];
            $algorithm = $this->config['jwt']['algorithm'] ?? 'RS256';
            
            // Verify token signature and decode payload
            $decoded = JWT::decode($token, new Key($publicKey, $algorithm));
            $payload = (array) $decoded;

            // Validate token claims
            $this->validateTokenClaims($payload);
            
            return $payload;
        } catch (Exception $e) {
            Log::warning('JWT token validation failed', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 20) . '...',
            ]);
            
            return null;
        }
    }

    /**
     * Get JWKS (JSON Web Key Set) for JWT signature verification.
     */
    protected function getJwks(): array
    {
        $jwksUri = $this->config['jwt']['jwks_uri'] ?? 'https://api.workos.com/.well-known/jwks.json';
        
        if ($this->cache && $this->config['cache']['enabled'] ?? true) {
            $cacheKey = $this->getCacheKey('jwks', 'keys');
            $ttl = $this->config['cache']['ttl']['jwt_keys'] ?? 86400;
            
            return $this->cache->remember($cacheKey, $ttl, function () use ($jwksUri) {
                return $this->fetchJwks($jwksUri);
            });
        }

        return $this->fetchJwks($jwksUri);
    }

    /**
     * Fetch JWKS from WorkOS.
     */
    protected function fetchJwks(string $jwksUri): array
    {
        try {
            $response = Http::timeout(10)->get($jwksUri);
            
            if (!$response->successful()) {
                throw new RuntimeException('Failed to fetch JWKS: ' . $response->status());
            }

            $jwks = $response->json();
            $keys = [];

            foreach ($jwks['keys'] ?? [] as $key) {
                if (isset($key['kid']) && isset($key['x5c'][0])) {
                    $cert = "-----BEGIN CERTIFICATE-----\n" . 
                           chunk_split($key['x5c'][0], 64, "\n") . 
                           "-----END CERTIFICATE-----\n";
                    $keys[$key['kid']] = $cert;
                }
            }

            return $keys;
        } catch (Exception $e) {
            Log::error('Failed to fetch JWKS', [
                'uri' => $jwksUri,
                'error' => $e->getMessage(),
            ]);
            
            throw new RuntimeException('Unable to fetch JWT verification keys', 0, $e);
        }
    }

    /**
     * Parse JWT header to extract metadata.
     */
    protected function parseJwtHeader(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid JWT format');
        }

        $header = json_decode(base64_decode($parts[0]), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidArgumentException('Invalid JWT header');
        }

        return $header;
    }

    /**
     * Validate JWT token claims (issuer, audience, expiration, etc.).
     */
    protected function validateTokenClaims(array $payload): void
    {
        $now = time();
        $clockSkew = $this->config['jwt']['clock_skew'] ?? 60;

        // Validate expiration
        if (isset($payload['exp']) && ($payload['exp'] + $clockSkew) < $now) {
            throw new InvalidArgumentException('JWT token has expired');
        }

        // Validate not before
        if (isset($payload['nbf']) && ($payload['nbf'] - $clockSkew) > $now) {
            throw new InvalidArgumentException('JWT token is not yet valid');
        }

        // Validate issuer
        $expectedIssuer = $this->config['jwt']['issuer'] ?? 'https://api.workos.com';
        if (isset($payload['iss']) && $payload['iss'] !== $expectedIssuer) {
            throw new InvalidArgumentException('Invalid JWT issuer');
        }

        // Validate audience
        $expectedAudience = $this->config['jwt']['audience'] ?? $this->config['client_id'];
        if ($expectedAudience && isset($payload['aud'])) {
            $audiences = is_array($payload['aud']) ? $payload['aud'] : [$payload['aud']];
            if (!in_array($expectedAudience, $audiences)) {
                throw new InvalidArgumentException('Invalid JWT audience');
            }
        }
    }

    /**
     * Insecure JWT decode for development/testing (DO NOT USE IN PRODUCTION).
     */
    protected function decodeJwtTokenInsecure(string $token): ?array
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }

            $payload = json_decode(base64_decode($parts[1]), true);
            
            // Basic validation - check expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return null;
            }

            return $payload;
        } catch (Exception $e) {
            Log::error('Failed to decode JWT token', [
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Extract all organizations with enhanced multi-organization support.
     */
    protected function extractOrganizations(array $userData): array
    {
        $organizations = [];
        
        if (isset($userData['organization_memberships'])) {
            foreach ($userData['organization_memberships'] as $membership) {
                $org = $membership['organization'] ?? [];
                $organizations[] = [
                    'id' => $org['id'] ?? null,
                    'name' => $org['name'] ?? null,
                    'slug' => $org['slug'] ?? null,
                    'role' => $membership['role']['slug'] ?? $membership['role'] ?? null,
                    'permissions' => $membership['permissions'] ?? [],
                    'status' => $membership['status'] ?? 'active',
                ];
            }
        }

        return $organizations;
    }

    /**
     * Extract permissions with hierarchical support.
     */
    protected function extractPermissions(array $userData): array
    {
        $permissions = [];

        // Direct permissions
        if (isset($userData['permissions'])) {
            $permissions = array_merge($permissions, $userData['permissions']);
        }

        // Organization-scoped permissions
        if (isset($userData['organization_memberships'])) {
            foreach ($userData['organization_memberships'] as $membership) {
                if (isset($membership['permissions'])) {
                    $permissions = array_merge($permissions, $membership['permissions']);
                }
            }
        }

        return array_unique($permissions);
    }

    /**
     * Extract roles with enhanced organization support.
     */
    protected function extractRoles(array $userData): array
    {
        $roles = [];

        // Direct roles
        if (isset($userData['roles'])) {
            $roles = array_merge($roles, $userData['roles']);
        }

        // Organization roles
        if (isset($userData['organization_memberships'])) {
            foreach ($userData['organization_memberships'] as $membership) {
                if (isset($membership['role'])) {
                    $role = $membership['role'];
                    $roleSlug = is_array($role) ? ($role['slug'] ?? null) : $role;
                    if ($roleSlug && !in_array($roleSlug, $roles)) {
                        $roles[] = $roleSlug;
                    }
                }
            }
        }

        return array_unique($roles);
    }

    /**
     * Extract primary organization ID with better logic.
     */
    protected function extractPrimaryOrganizationId(array $userData): ?string
    {
        if (isset($userData['organization_memberships']) && !empty($userData['organization_memberships'])) {
            // Sort by role priority (admin > manager > member) and take the first
            $memberships = $userData['organization_memberships'];
            usort($memberships, function ($a, $b) {
                $roleA = $a['role']['slug'] ?? $a['role'] ?? '';
                $roleB = $b['role']['slug'] ?? $b['role'] ?? '';
                
                $priority = ['admin' => 3, 'manager' => 2, 'member' => 1];
                $prioA = $priority[$roleA] ?? 0;
                $prioB = $priority[$roleB] ?? 0;
                
                return $prioB - $prioA;
            });
            
            return $memberships[0]['organization']['id'] ?? null;
        }

        return null;
    }

    /**
     * Get user from cache.
     */
    protected function getUserFromCache(string $userId): ?WorkOSUser
    {
        if (!$this->cache || !($this->config['cache']['enabled'] ?? true)) {
            return null;
        }

        $cacheKey = $this->getCacheKey('user', $userId);
        $userData = $this->cache->get($cacheKey);
        
        return $userData ? $this->createWorkOSUser($userData) : null;
    }

    /**
     * Cache user data for performance.
     */
    protected function cacheUser(WorkOSUser $user): void
    {
        if (!$this->cache || !($this->config['cache']['enabled'] ?? true)) {
            return;
        }

        $cacheKey = $this->getCacheKey('user', $user->getWorkOSId());
        $ttl = $this->config['cache']['ttl']['user'] ?? 3600;
        
        $this->cache->put($cacheKey, $user->getRawData(), $ttl);
    }

    /**
     * Generate cache key.
     */
    protected function getCacheKey(string $type, string $identifier): string
    {
        $prefix = $this->config['cache']['prefix'] ?? 'workos';
        return "{$prefix}:{$type}:{$identifier}";
    }

    /**
     * Refresh user cache by clearing it.
     */
    public function refreshUserCache(string $userId): void
    {
        if (!$this->cache) {
            return;
        }

        $cacheKey = $this->getCacheKey('user', $userId);
        $this->cache->forget($cacheKey);
    }

    /**
     * Clear all user cache.
     */
    public function clearUserCache(): void
    {
        if (!$this->cache) {
            return;
        }

        // This is a simplified implementation
        // In production, you might want to use cache tags
        $this->cache->flush();
    }
}