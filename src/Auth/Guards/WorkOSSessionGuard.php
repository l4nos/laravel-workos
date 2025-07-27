<?php

declare(strict_types=1);

namespace LaravelWorkOS\Auth\Guards;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use LaravelWorkOS\Services\AuthKitService;
use LaravelWorkOS\Services\SessionService;
use RuntimeException;

class WorkOSSessionGuard implements StatefulGuard
{
    protected UserProvider $provider;
    protected SessionManager $session;
    protected Request $request;
    protected SessionService $sessionService;
    protected AuthKitService $authKit;
    protected ?Authenticatable $user = null;
    protected bool $loggedOut = false;
    protected string $name;

    public function __construct(
        UserProvider $provider,
        SessionManager $session,
        Request $request,
        SessionService $sessionService,
        AuthKitService $authKit,
        string $name = 'workos-session'
    ) {
        $this->provider = $provider;
        $this->session = $session;
        $this->request = $request;
        $this->sessionService = $sessionService;
        $this->authKit = $authKit;
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
     * Get the currently authenticated user.
     */
    public function user(): ?Authenticatable
    {
        if ($this->loggedOut) {
            return null;
        }

        if (!is_null($this->user)) {
            return $this->user;
        }

        try {
            // Get sealed session data
            $sessionData = $this->sessionService->getSealedSession();
            
            if (!$sessionData) {
                return null;
            }

            // Check if session needs refresh
            if ($this->sessionService->shouldRefreshSession($sessionData)) {
                $sessionData = $this->refreshUserSession($sessionData);
                if (!$sessionData) {
                    return null;
                }
            }

            // Create user from session data
            if (isset($sessionData['user']) && $this->provider instanceof \LaravelWorkOS\Auth\Providers\WorkOSUserProvider) {
                $this->user = $this->provider->createWorkOSUser($sessionData['user']);
                
                $this->logSessionEvent('user_retrieved_from_session', [
                    'user_id' => $this->user instanceof WorkOSUser ? $this->user->getWorkOSId() : null,
                    'organization_id' => $sessionData['organization_id'] ?? null,
                ]);
            }
        } catch (Exception $e) {
            Log::error('WorkOS Session Guard: Failed to retrieve user from session', [
                'error' => $e->getMessage(),
                'session_id' => $this->session->getId(),
            ]);

            // Clear invalid session
            $this->sessionService->clearSession();
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
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        // For session guard, we validate through AuthKit callback
        if (isset($credentials['code']) && isset($credentials['state'])) {
            try {
                $result = $this->authKit->processCallback($credentials['code'], $credentials['state']);
                return !empty($result['user']);
            } catch (Exception $e) {
                Log::error('WorkOS Session Guard: Failed to validate AuthKit callback', [
                    'error' => $e->getMessage(),
                ]);
                return false;
            }
        }

        return false;
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool
    {
        // WorkOS sessions handle persistence, so this is always false
        return false;
    }

    /**
     * Log a user into the application.
     */
    public function login(Authenticatable $user, $remember = false): void
    {
        $this->setUser($user);
        
        // For WorkOS users, we should have session data
        if ($user instanceof WorkOSUser) {
            $this->logSessionEvent('user_logged_in', [
                'user_id' => $user instanceof WorkOSUser ? $user->getWorkOSId() : null,
                'remember' => $remember,
            ]);
        }

        $this->session->regenerate();
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
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool
    {
        // Not supported for session-based authentication
        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
    public function onceUsingId($id): ?Authenticatable
    {
        // Not supported for session-based authentication
        return null;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     */
    public function attempt(array $credentials = [], $remember = false): bool
    {
        // For session guard, attempt means processing AuthKit callback
        if (isset($credentials['code']) && isset($credentials['state'])) {
            try {
                $result = $this->authKit->processCallback($credentials['code'], $credentials['state']);
                
                if (!empty($result['user'])) {
                    // Create sealed session
                    $sessionData = $this->sessionService->createSealedSession($result);
                    
                    // Create user instance
                    if ($this->provider instanceof \LaravelWorkOS\Auth\Providers\WorkOSUserProvider) {
                        $user = $this->provider->createWorkOSUser($result['user']);
                    } else {
                        return false;
                    }
                    $this->login($user, $remember);
                    
                    $this->logSessionEvent('authentication_successful', [
                        'user_id' => $user instanceof WorkOSUser ? $user->getWorkOSId() : null,
                        'organization_id' => $result['organization_id'] ?? null,
                    ]);
                    
                    return true;
                }
            } catch (Exception $e) {
                Log::error('WorkOS Session Guard: Authentication attempt failed', [
                    'error' => $e->getMessage(),
                ]);
                
                $this->logSessionEvent('authentication_failed', [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return false;
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        $user = $this->user;
        
        if ($user instanceof WorkOSUser) {
            $this->logSessionEvent('user_logging_out', [
                'user_id' => $user->getWorkOSId(),
            ]);
        }

        // Clear the sealed session
        $this->sessionService->clearSession();
        
        // Clear Laravel session data
        $this->session->invalidate();
        $this->session->regenerateToken();
        
        $this->user = null;
        $this->loggedOut = true;
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
     * Generate authorization URL for AuthKit authentication.
     */
    public function generateAuthUrl(array $options = []): string
    {
        $defaultOptions = [
            'redirect_uri' => $this->request->fullUrl(),
        ];

        $options = array_merge($defaultOptions, $options);
        
        $authUrl = $this->authKit->generateAuthorizationUrl($options);
        
        $this->logSessionEvent('auth_url_generated', [
            'organization' => $options['organization'] ?? null,
            'redirect_uri' => $options['redirect_uri'],
        ]);
        
        return $authUrl;
    }

    /**
     * Generate logout URL for WorkOS.
     */
    public function generateLogoutUrl(): string
    {
        $sessionData = $this->sessionService->getSealedSession();
        $sessionId = $sessionData['session_id'] ?? null;
        
        $logoutUrl = $this->authKit->generateLogoutUrl($sessionId);
        
        $this->logSessionEvent('logout_url_generated', [
            'session_id' => $sessionId,
        ]);
        
        return $logoutUrl;
    }

    /**
     * Refresh the user's session.
     */
    public function refreshSession(): bool
    {
        try {
            $sessionData = $this->sessionService->getSealedSession();
            
            if (!$sessionData) {
                return false;
            }

            $refreshedData = $this->sessionService->refreshSession($sessionData);
            
            if ($refreshedData) {
                // Update user instance with fresh data
                if (isset($refreshedData['user']) && $this->provider instanceof \LaravelWorkOS\Auth\Providers\WorkOSUserProvider) {
                    $this->user = $this->provider->createWorkOSUser($refreshedData['user']);
                }
                
                $this->logSessionEvent('session_refreshed', [
                    'user_id' => $this->user instanceof WorkOSUser ? $this->user->getWorkOSId() : null,
                ]);
                
                return true;
            }
        } catch (Exception $e) {
            Log::error('WorkOS Session Guard: Failed to refresh session', [
                'error' => $e->getMessage(),
            ]);
            
            $this->logSessionEvent('session_refresh_failed', [
                'error' => $e->getMessage(),
            ]);
        }

        return false;
    }

    /**
     * Check if the current session needs refresh.
     */
    public function sessionNeedsRefresh(): bool
    {
        $sessionData = $this->sessionService->getSealedSession();
        return $sessionData ? $this->sessionService->shouldRefreshSession($sessionData) : false;
    }

    /**
     * Get session statistics.
     */
    public function getSessionStats(): array
    {
        return array_merge(
            $this->sessionService->getSessionStats(),
            [
                'guard_name' => $this->name,
                'authenticated' => $this->check(),
                'user_id' => $this->id(),
                'needs_refresh' => $this->sessionNeedsRefresh(),
            ]
        );
    }

    /**
     * Switch user to a different organization.
     */
    public function switchOrganization(string $organizationId): bool
    {
        $user = $this->user();
        
        if (!$user instanceof WorkOSUser) {
            return false;
        }

        if (!$user->belongsToOrganization($organizationId)) {
            $this->logSessionEvent('organization_switch_denied', [
                'user_id' => $user->getWorkOSId(),
                'target_organization_id' => $organizationId,
                'reason' => 'user_not_member',
            ]);
            return false;
        }

        // Update user's active organization
        $success = $user->switchOrganization($organizationId);
        
        if ($success) {
            // Update session data
            $sessionData = $this->sessionService->getSealedSession();
            if ($sessionData) {
                $sessionData['organization_id'] = $organizationId;
                $this->sessionService->updateSession($sessionData);
            }
            
            $this->logSessionEvent('organization_switched', [
                'user_id' => $user->getWorkOSId(),
                'new_organization_id' => $organizationId,
            ]);
        }
        
        return $success;
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
     * Get the session manager.
     */
    public function getSession(): SessionManager
    {
        return $this->session;
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
     * Refresh user session data.
     */
    protected function refreshUserSession(array $sessionData): ?array
    {
        try {
            return $this->sessionService->refreshSession($sessionData);
        } catch (Exception $e) {
            Log::warning('WorkOS Session Guard: Session refresh failed', [
                'error' => $e->getMessage(),
                'user_id' => $sessionData['user']['id'] ?? null,
            ]);

            // Clear invalid session
            $this->sessionService->clearSession();
            return null;
        }
    }

    /**
     * Log session-related events.
     */
    protected function logSessionEvent(string $event, array $context = []): void
    {
        $logContext = array_merge([
            'guard' => $this->name,
            'event' => $event,
            'timestamp' => time(),
            'session_id' => $this->session->getId(),
            'ip_address' => $this->request->ip(),
            'user_agent' => $this->request->userAgent(),
        ], $context);

        Log::info("WorkOS Session Guard: {$event}", $logContext);
    }

    /**
     * Get the guard name.
     */
    public function getName(): string
    {
        return $this->name;
    }
}