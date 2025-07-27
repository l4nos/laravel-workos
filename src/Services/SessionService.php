<?php

declare(strict_types=1);

namespace LaravelWorkOS\Services;

use Exception;
use Illuminate\Cookie\CookieJar;
use Illuminate\Session\SessionManager;
use InvalidArgumentException;
use RuntimeException;

class SessionService
{
    protected WorkOSService $workos;
    protected array $config;
    protected SessionManager $session;
    protected CookieJar $cookie;

    public function __construct(
        WorkOSService $workos,
        array $config,
        SessionManager $session,
        CookieJar $cookie
    ) {
        $this->workos = $workos;
        $this->config = $config;
        $this->session = $session;
        $this->cookie = $cookie;
    }

    /**
     * Create a sealed session from WorkOS authentication data.
     */
    public function createSealedSession(array $authData): array
    {
        try {
            $sessionData = [
                'access_token' => $authData['access_token'],
                'refresh_token' => $authData['refresh_token'] ?? null,
                'user' => $authData['user'],
                'organization_id' => $authData['organization_id'] ?? null,
                'expires_at' => $authData['expires_at'] ?? null,
                'created_at' => time(),
                'last_activity' => time(),
            ];

            // Encrypt session data for security
            $sealedData = $this->encryptSessionData($sessionData);
            
            // Store in Laravel session
            $this->session->put('workos_sealed_session', $sealedData);
            
            // Create secure cookie
            $this->createSessionCookie($sealedData);
            
            $this->logSessionEvent('session_created', [
                'user_id' => $authData['user']['id'] ?? null,
                'organization_id' => $authData['organization_id'] ?? null,
            ]);

            return $sessionData;
        } catch (Exception $e) {
            $this->logSessionEvent('session_creation_failed', [
                'error' => $e->getMessage(),
            ]);

            throw new RuntimeException(
                'Failed to create sealed session: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Retrieve and validate sealed session data.
     */
    public function getSealedSession(): ?array
    {
        try {
            // Try to get from Laravel session first
            $sealedData = $this->session->get('workos_sealed_session');
            
            // Fallback to cookie if not in session
            if (!$sealedData) {
                $cookieName = $this->config['session']['cookie'] ?? 'workos-session';
                $sealedData = $this->cookie->get($cookieName);
            }

            if (!$sealedData) {
                return null;
            }

            // Decrypt and validate session data
            $sessionData = $this->decryptSessionData($sealedData);
            
            if (!$this->isSessionValid($sessionData)) {
                $this->clearSession();
                return null;
            }

            // Update last activity
            $sessionData['last_activity'] = time();
            $this->updateSession($sessionData);

            return $sessionData;
        } catch (Exception $e) {
            $this->logSessionEvent('session_retrieval_failed', [
                'error' => $e->getMessage(),
            ]);

            // Clear invalid session
            $this->clearSession();
            return null;
        }
    }

    /**
     * Refresh an expired or expiring session.
     */
    public function refreshSession(array $sessionData): ?array
    {
        if (!isset($sessionData['refresh_token'])) {
            throw new InvalidArgumentException('Refresh token is required to refresh session');
        }

        try {
            // Use AuthKit service to refresh the session
            $authKit = app('workos.auth');
            $refreshedData = $authKit->refreshSession($sessionData['refresh_token']);

            // Merge with existing session data
            $newSessionData = array_merge($sessionData, [
                'access_token' => $refreshedData['access_token'],
                'refresh_token' => $refreshedData['refresh_token'] ?? $sessionData['refresh_token'],
                'user' => $refreshedData['user'],
                'expires_at' => $refreshedData['expires_at'],
                'last_activity' => time(),
                'refreshed_at' => time(),
            ]);

            // Update the sealed session
            $this->updateSession($newSessionData);

            $this->logSessionEvent('session_refreshed', [
                'user_id' => $newSessionData['user']['id'] ?? null,
            ]);

            return $newSessionData;
        } catch (Exception $e) {
            $this->logSessionEvent('session_refresh_failed', [
                'error' => $e->getMessage(),
            ]);

            throw new RuntimeException(
                'Failed to refresh session: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Update existing session data.
     */
    public function updateSession(array $sessionData): void
    {
        try {
            // Encrypt updated session data
            $sealedData = $this->encryptSessionData($sessionData);
            
            // Update Laravel session
            $this->session->put('workos_sealed_session', $sealedData);
            
            // Update cookie
            $this->createSessionCookie($sealedData);
        } catch (Exception $e) {
            $this->logSessionEvent('session_update_failed', [
                'error' => $e->getMessage(),
            ]);

            throw new RuntimeException(
                'Failed to update session: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Clear the sealed session.
     */
    public function clearSession(): void
    {
        try {
            // Remove from Laravel session
            $this->session->forget('workos_sealed_session');
            
            // Clear cookie
            $cookieName = $this->config['session']['cookie'] ?? 'workos-session';
            $this->cookie->forget($cookieName);

            $this->logSessionEvent('session_cleared');
        } catch (Exception $e) {
            $this->logSessionEvent('session_clear_failed', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Check if session needs to be refreshed.
     */
    public function shouldRefreshSession(array $sessionData): bool
    {
        if (!isset($sessionData['expires_at']) || !$sessionData['expires_at']) {
            return false;
        }

        $threshold = $this->config['session']['refresh_threshold'] ?? 3600; // 1 hour
        return ($sessionData['expires_at'] - time()) < $threshold;
    }

    /**
     * Validate session data integrity and expiration.
     */
    protected function isSessionValid(array $sessionData): bool
    {
        // Check for required fields
        $requiredFields = ['access_token', 'user', 'created_at'];
        foreach ($requiredFields as $field) {
            if (!isset($sessionData[$field])) {
                return false;
            }
        }

        // Check expiration
        if (isset($sessionData['expires_at']) && $sessionData['expires_at']) {
            if (time() > $sessionData['expires_at']) {
                return false;
            }
        }

        // Check session lifetime
        $maxLifetime = $this->config['session']['lifetime'] ?? 86400; // 24 hours
        if (time() - $sessionData['created_at'] > $maxLifetime) {
            return false;
        }

        // Check for suspicious activity (optional)
        if ($this->detectSuspiciousActivity($sessionData)) {
            return false;
        }

        return true;
    }

    /**
     * Encrypt session data for secure storage.
     */
    protected function encryptSessionData(array $sessionData): string
    {
        $cookiePassword = $this->config['cookie_password'];
        
        if (strlen($cookiePassword) !== 32) {
            throw new InvalidArgumentException('Cookie password must be exactly 32 characters');
        }

        // Use Laravel's encryption if available, otherwise use simple encryption
        if (function_exists('encrypt')) {
            return encrypt(json_encode($sessionData));
        }

        // Fallback encryption using AES-256-GCM
        $data = json_encode($sessionData);
        $iv = random_bytes(16);
        $key = hash('sha256', $cookiePassword, true);
        
        $encrypted = openssl_encrypt($data, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag);
        
        if ($encrypted === false) {
            throw new RuntimeException('Failed to encrypt session data');
        }

        return base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Decrypt session data.
     */
    protected function decryptSessionData(string $sealedData): array
    {
        $cookiePassword = $this->config['cookie_password'];
        
        // Use Laravel's decryption if available
        if (function_exists('decrypt')) {
            try {
                $decrypted = decrypt($sealedData);
                return json_decode($decrypted, true) ?: [];
            } catch (Exception $e) {
                throw new RuntimeException('Failed to decrypt session data: ' . $e->getMessage());
            }
        }

        // Fallback decryption
        $data = base64_decode($sealedData);
        if ($data === false || strlen($data) < 32) {
            throw new RuntimeException('Invalid sealed session data');
        }

        $iv = substr($data, 0, 16);
        $tag = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        $key = hash('sha256', $cookiePassword, true);

        $decrypted = openssl_decrypt($encrypted, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag);
        
        if ($decrypted === false) {
            throw new RuntimeException('Failed to decrypt session data');
        }

        return json_decode($decrypted, true) ?: [];
    }

    /**
     * Create a secure session cookie.
     */
    protected function createSessionCookie(string $sealedData): void
    {
        $cookieName = $this->config['session']['cookie'] ?? 'workos-session';
        $lifetime = $this->config['session']['lifetime'] ?? 86400;
        $secure = $this->config['session']['secure'] ?? request()->isSecure();
        $sameSite = $this->config['session']['same_site'] ?? 'lax';

        $this->cookie->queue(
            $cookieName,
            $sealedData,
            $lifetime / 60, // Convert to minutes
            '/',
            null,
            $secure,
            true, // httpOnly
            false,
            $sameSite
        );
    }

    /**
     * Detect suspicious session activity.
     */
    protected function detectSuspiciousActivity(array $sessionData): bool
    {
        // Check for excessive session age without activity
        if (isset($sessionData['last_activity'])) {
            $inactiveTime = time() - $sessionData['last_activity'];
            $maxInactiveTime = 7200; // 2 hours
            
            if ($inactiveTime > $maxInactiveTime) {
                return true;
            }
        }

        // Add more suspicious activity checks as needed
        // - IP address changes
        // - User agent changes
        // - Unusual access patterns

        return false;
    }

    /**
     * Clean up expired sessions.
     */
    public function cleanupExpiredSessions(): int
    {
        // This is a placeholder implementation
        // In a real implementation, you might store session metadata
        // and clean up expired sessions from storage
        
        $cleaned = 0;
        
        $this->logSessionEvent('session_cleanup_completed', [
            'sessions_cleaned' => $cleaned,
        ]);
        
        return $cleaned;
    }

    /**
     * Get session statistics.
     */
    public function getSessionStats(): array
    {
        $currentSession = $this->getSealedSession();
        
        return [
            'has_active_session' => $currentSession !== null,
            'session_age' => $currentSession ? time() - $currentSession['created_at'] : null,
            'time_until_expiry' => $currentSession && isset($currentSession['expires_at']) 
                ? max(0, $currentSession['expires_at'] - time()) 
                : null,
            'needs_refresh' => $currentSession ? $this->shouldRefreshSession($currentSession) : false,
        ];
    }

    /**
     * Log session events for debugging and monitoring.
     */
    protected function logSessionEvent(string $event, array $context = []): void
    {
        if (!($this->config['logging']['events']['authentication'] ?? true)) {
            return;
        }

        $logContext = array_merge([
            'event' => $event,
            'timestamp' => time(),
            'session_id' => session_id(),
        ], $context);

        logger()->info("WorkOS Session: {$event}", $logContext);
    }
}