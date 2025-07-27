<?php

declare(strict_types=1);

namespace LaravelWorkOS\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Str;
use InvalidArgumentException;
use RuntimeException;

class AuthKitService
{
    protected WorkOSService $workos;
    protected array $config;
    protected SessionManager $session;
    protected Request $request;
    protected array $stateStorage = [];

    public function __construct(
        WorkOSService $workos,
        array $config,
        SessionManager $session,
        Request $request
    ) {
        $this->workos = $workos;
        $this->config = $config;
        $this->session = $session;
        $this->request = $request;
    }

    /**
     * Generate an authorization URL for WorkOS AuthKit.
     */
    public function generateAuthorizationUrl(array $options = []): string
    {
        $state = $this->generateState();
        $this->storeState($state, $options);

        $params = [
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $options['redirect_uri'] ?? $this->config['redirects']['callback'],
            'response_type' => 'code',
            'state' => $state,
        ];

        // Add organization parameter if specified
        if (!empty($options['organization'])) {
            $params['organization'] = $options['organization'];
        }

        // Add domain hint if specified
        if (!empty($options['domain_hint'])) {
            $params['domain_hint'] = $options['domain_hint'];
        }

        // Add login hint if specified
        if (!empty($options['login_hint'])) {
            $params['login_hint'] = $options['login_hint'];
        }

        // Add custom parameters
        if (!empty($options['custom_params']) && is_array($options['custom_params'])) {
            $params = array_merge($params, $options['custom_params']);
        }

        $baseUrl = $this->config['api']['base_url'] ?? 'https://api.workos.com';
        $authUrl = "{$baseUrl}/sso/authorize?" . http_build_query($params);

        $this->logAuthEvent('authorization_url_generated', [
            'organization' => $options['organization'] ?? null,
            'domain_hint' => $options['domain_hint'] ?? null,
            'state' => $state,
        ]);

        return $authUrl;
    }

    /**
     * Process the authorization callback and exchange code for user session.
     */
    public function processCallback(?string $code = null, ?string $state = null): array
    {
        $code = $code ?? $this->request->query('code');
        $state = $state ?? $this->request->query('state');
        $error = $this->request->query('error');
        $errorDescription = $this->request->query('error_description');

        // Handle errors from WorkOS
        if ($error) {
            $this->logAuthEvent('callback_error', [
                'error' => $error,
                'error_description' => $errorDescription,
            ]);

            throw new RuntimeException(
                "AuthKit callback error: {$error}" . 
                ($errorDescription ? " - {$errorDescription}" : '')
            );
        }

        // Validate required parameters
        if (!$code) {
            throw new InvalidArgumentException('Authorization code is required');
        }

        if (!$state) {
            throw new InvalidArgumentException('State parameter is required');
        }

        // Validate state parameter to prevent CSRF attacks
        if ($this->config['security']['validate_state'] ?? true) {
            $this->validateState($state);
        }

        try {
            // Exchange authorization code for access token and user info
            $result = $this->exchangeCodeForSession($code);

            $this->logAuthEvent('callback_success', [
                'user_id' => $result['user']['id'] ?? null,
                'organization_id' => $result['organization_id'] ?? null,
            ]);

            return $result;
        } catch (Exception $e) {
            $this->logAuthEvent('callback_failed', [
                'error' => $e->getMessage(),
            ]);

            throw new RuntimeException(
                'Failed to process authorization callback: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Exchange authorization code for user session data.
     */
    protected function exchangeCodeForSession(string $code): array
    {
        return $this->workos->executeWithRetry(function () use ($code) {
            $response = $this->workos->getUserManagement()->authenticateWithCode(
                $this->config['client_id'],
                $code,
                $this->request->ip(),
                $this->request->userAgent()
            );

            // Convert WorkOS response to array
            if (method_exists($response, 'toArray')) {
                $data = $response->toArray();
            } else {
                // Fallback for different response formats
                $data = json_decode(json_encode($response), true);
            }

            return [
                'access_token' => $data['access_token'] ?? null,
                'refresh_token' => $data['refresh_token'] ?? null,
                'user' => $data['user'] ?? $data['profile'] ?? [],
                'organization_id' => $data['organization_id'] ?? null,
                'expires_at' => $this->calculateExpirationTime($data),
            ];
        }, 'exchange_code_for_session');
    }

    /**
     * Generate logout URL for WorkOS AuthKit.
     */
    public function generateLogoutUrl(?string $sessionId = null): string
    {
        $params = [
            'client_id' => $this->config['client_id'],
        ];

        // Add session ID if provided
        if ($sessionId) {
            $params['session_id'] = $sessionId;
        }

        $baseUrl = $this->config['api']['base_url'] ?? 'https://api.workos.com';
        $logoutUrl = "{$baseUrl}/sso/logout?" . http_build_query($params);

        $this->logAuthEvent('logout_url_generated', [
            'session_id' => $sessionId,
        ]);

        return $logoutUrl;
    }

    /**
     * Refresh an expired session using refresh token.
     */
    public function refreshSession(string $refreshToken): array
    {
        try {
            return $this->workos->executeWithRetry(function () use ($refreshToken) {
                $response = $this->workos->getUserManagement()->authenticateWithRefreshToken(
                    $this->config['client_id'],
                    $refreshToken,
                    $this->request->ip(),
                    $this->request->userAgent(),
                    null // organizationId
                );

                // Convert WorkOS response to array
                if (method_exists($response, 'toArray')) {
                    $data = $response->toArray();
                } else {
                    $data = json_decode(json_encode($response), true);
                }

                $this->logAuthEvent('session_refreshed', [
                    'user_id' => $data['user']['id'] ?? null,
                ]);

                return [
                    'access_token' => $data['access_token'] ?? null,
                    'refresh_token' => $data['refresh_token'] ?? null,
                    'user' => $data['user'] ?? $data['profile'] ?? [],
                    'expires_at' => $this->calculateExpirationTime($data),
                ];
            }, 'refresh_session');
        } catch (Exception $e) {
            $this->logAuthEvent('session_refresh_failed', [
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
     * Validate user session and return user data.
     */
    public function validateSession(string $accessToken): ?array
    {
        try {
            return $this->workos->executeWithRetry(function () use ($accessToken) {
                // Use the access token to get current user information
                $user = $this->workos->getUserManagement()->getUser($accessToken);
                
                return $user ? $user->toArray() : null;
            }, 'validate_session');
        } catch (Exception $e) {
            $this->logAuthEvent('session_validation_failed', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * Generate a secure state parameter for CSRF protection.
     */
    protected function generateState(): string
    {
        $length = $this->config['security']['state_parameter_length'] ?? 32;
        return Str::random($length);
    }

    /**
     * Store state parameter in session for validation.
     */
    protected function storeState(string $state, array $options = []): void
    {
        $stateData = [
            'state' => $state,
            'timestamp' => time(),
            'options' => $options,
        ];

        $this->session->put('workos_auth_state', $stateData);
        $this->stateStorage[$state] = $stateData;
    }

    /**
     * Validate state parameter to prevent CSRF attacks.
     */
    protected function validateState(string $state): void
    {
        $storedData = $this->session->get('workos_auth_state');
        
        if (!$storedData || !is_array($storedData)) {
            throw new InvalidArgumentException('Invalid or missing state parameter');
        }

        if ($storedData['state'] !== $state) {
            throw new InvalidArgumentException('State parameter mismatch - possible CSRF attack');
        }

        // Check if state is not too old (prevent replay attacks)
        $maxAge = 600; // 10 minutes
        if (time() - $storedData['timestamp'] > $maxAge) {
            throw new InvalidArgumentException('State parameter expired');
        }

        // Clear the state after successful validation
        $this->session->forget('workos_auth_state');
    }

    /**
     * Calculate token expiration time.
     */
    protected function calculateExpirationTime(array $tokenData): ?int
    {
        if (isset($tokenData['expires_in'])) {
            return time() + (int) $tokenData['expires_in'];
        }

        if (isset($tokenData['expires_at'])) {
            return (int) $tokenData['expires_at'];
        }

        // Default expiration (24 hours)
        $defaultLifetime = $this->config['session']['lifetime'] ?? 86400;
        return time() + $defaultLifetime;
    }

    /**
     * Get organization information for organization-scoped authentication.
     */
    public function getOrganizationFromDomain(string $domain): ?array
    {
        try {
            return $this->workos->executeWithRetry(function () use ($domain) {
                $organizations = $this->workos->getOrganizations()->listOrganizations(
                    [$domain], // domains
                    null,      // before
                    null,      // after
                    1          // limit
                );

                // Handle array response directly (the method returns an array)
                if (is_array($organizations) && !empty($organizations[2])) {
                    // The third element contains the Organization[] array
                    foreach ($organizations[2] as $org) {
                        if (method_exists($org, 'toArray')) {
                            $orgData = $org->toArray();
                            if (isset($orgData['domains']) && in_array($domain, $orgData['domains'])) {
                                return $orgData;
                            }
                        }
                    }
                }

                return null;
            }, 'get_organization_from_domain');
        } catch (Exception $e) {
            $this->logAuthEvent('organization_lookup_failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * Check if session needs refresh based on expiration time.
     */
    public function shouldRefreshSession(?int $expiresAt): bool
    {
        if (!$expiresAt) {
            return false;
        }

        $threshold = $this->config['session']['refresh_threshold'] ?? 3600; // 1 hour
        return ($expiresAt - time()) < $threshold;
    }

    /**
     * Log authentication events for debugging and monitoring.
     */
    protected function logAuthEvent(string $event, array $context = []): void
    {
        if (!($this->config['logging']['events']['authentication'] ?? true)) {
            return;
        }

        $logContext = array_merge([
            'event' => $event,
            'timestamp' => now()->toISOString(),
            'ip_address' => $this->request->ip(),
            'user_agent' => $this->request->userAgent(),
        ], $context);

        logger()->info("WorkOS AuthKit: {$event}", $logContext);
    }

    /**
     * Get stored state data.
     */
    public function getStoredStateData(): ?array
    {
        return $this->session->get('workos_auth_state');
    }

    /**
     * Clear stored state data.
     */
    public function clearStoredState(): void
    {
        $this->session->forget('workos_auth_state');
    }
}