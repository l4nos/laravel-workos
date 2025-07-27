<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | WorkOS API Configuration
    |--------------------------------------------------------------------------
    |
    | Your WorkOS API credentials and configuration settings. These values
    | are used to configure the WorkOS PHP SDK and authenticate requests.
    |
    */

    'api_key' => env('WORKOS_API_KEY'),
    'client_id' => env('WORKOS_CLIENT_ID'),
    'cookie_password' => env('WORKOS_COOKIE_PASSWORD'),


    /*
    |--------------------------------------------------------------------------
    | Redirect URI Configuration
    |--------------------------------------------------------------------------
    |
    | These settings control the various redirect URIs used throughout
    | the authentication flow with WorkOS AuthKit.
    |
    */

    'redirects' => [
        'login' => env('WORKOS_LOGIN_URI', '/login'),
        'callback' => env('WORKOS_REDIRECT_URI', '/auth/callback'),
        'logout' => env('WORKOS_LOGOUT_REDIRECT', '/'),
        'after_login' => env('WORKOS_AFTER_LOGIN_REDIRECT', '/dashboard'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Configuration
    |--------------------------------------------------------------------------
    |
    | These options control the behavior of WorkOS sealed sessions,
    | including lifetime, cookie settings, and refresh behavior.
    |
    */

    'session' => [
        'lifetime' => (int) env('WORKOS_SESSION_LIFETIME', 86400), // 24 hours
        'cookie' => env('WORKOS_SESSION_COOKIE', 'workos-session'),
        'auto_refresh' => env('WORKOS_SESSION_AUTO_REFRESH', true),
        'refresh_threshold' => (int) env('WORKOS_SESSION_REFRESH_THRESHOLD', 3600), // 1 hour
        'secure' => env('WORKOS_SESSION_SECURE', null), // Auto-detect based on HTTPS
        'same_site' => env('WORKOS_SESSION_SAME_SITE', 'lax'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Caching Configuration
    |--------------------------------------------------------------------------
    |
    | These settings control the caching behavior for user data, permissions,
    | and other WorkOS API responses to improve performance.
    |
    */

    'cache' => [
        'enabled' => env('WORKOS_CACHE_ENABLED', true),
        'store' => env('WORKOS_CACHE_STORE', null), // Uses default cache store
        'prefix' => env('WORKOS_CACHE_PREFIX', 'workos'),
        'ttl' => [
            'user' => (int) env('WORKOS_CACHE_USER_TTL', 3600), // 1 hour
            'permissions' => (int) env('WORKOS_CACHE_PERMISSIONS_TTL', 1800), // 30 minutes
            'organizations' => (int) env('WORKOS_CACHE_ORGANIZATIONS_TTL', 7200), // 2 hours
            'jwt_keys' => (int) env('WORKOS_CACHE_JWT_KEYS_TTL', 86400), // 24 hours
            'tokens' => (int) env('WORKOS_CACHE_TOKENS_TTL', 300), // 5 minutes
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for JWT token validation, including signature verification
    | and security parameters.
    |
    */

    'jwt' => [
        'verify_signature' => env('WORKOS_JWT_VERIFY_SIGNATURE', true),
        'clock_skew' => (int) env('WORKOS_JWT_CLOCK_SKEW', 60), // seconds
        'algorithm' => env('WORKOS_JWT_ALGORITHM', 'RS256'),
        'jwks_uri' => env('WORKOS_JWKS_URI', 'https://api.workos.com/.well-known/jwks.json'),
        'issuer' => env('WORKOS_JWT_ISSUER', 'https://api.workos.com'),
        'audience' => env('WORKOS_JWT_AUDIENCE', null), // Will use client_id if null
    ],

    /*
    |--------------------------------------------------------------------------
    | API Client Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for the WorkOS API client including timeouts, retry logic,
    | and rate limiting configuration.
    |
    */

    'api' => [
        'timeout' => (int) env('WORKOS_API_TIMEOUT', 30),
        'connect_timeout' => (int) env('WORKOS_API_CONNECT_TIMEOUT', 10),
        'retry_attempts' => (int) env('WORKOS_API_RETRY_ATTEMPTS', 3),
        'retry_delay' => (int) env('WORKOS_API_RETRY_DELAY', 1000), // milliseconds
        'base_url' => env('WORKOS_API_BASE_URL', 'https://api.workos.com'),
        'user_agent' => env('WORKOS_USER_AGENT', 'LaravelWorkOS/1.0'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting Configuration
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting behavior to comply with WorkOS API limits
    | and implement circuit breaker patterns.
    |
    */

    'rate_limiting' => [
        'enabled' => env('WORKOS_RATE_LIMITING_ENABLED', true),
        'requests_per_minute' => (int) env('WORKOS_RATE_LIMIT_RPM', 60),
        'burst_limit' => (int) env('WORKOS_RATE_LIMIT_BURST', 10),
        'circuit_breaker' => [
            'enabled' => env('WORKOS_CIRCUIT_BREAKER_ENABLED', true),
            'failure_threshold' => (int) env('WORKOS_CIRCUIT_BREAKER_THRESHOLD', 5),
            'recovery_timeout' => (int) env('WORKOS_CIRCUIT_BREAKER_RECOVERY', 60),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Organization Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for multi-organization support including organization
    | detection and context switching.
    |
    */

    'organizations' => [
        'multi_org_support' => env('WORKOS_MULTI_ORG_SUPPORT', true),
        'organization_detection' => [
            'subdomain' => env('WORKOS_ORG_DETECTION_SUBDOMAIN', false),
            'domain' => env('WORKOS_ORG_DETECTION_DOMAIN', false),
            'parameter' => env('WORKOS_ORG_DETECTION_PARAMETER', true),
        ],
        'default_organization' => env('WORKOS_DEFAULT_ORGANIZATION', null),
        'organization_switching' => env('WORKOS_ORG_SWITCHING_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Permission System Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the RBAC permission system including caching and
    | inheritance behavior.
    |
    */

    'permissions' => [
        'cache_permissions' => env('WORKOS_CACHE_PERMISSIONS', true),
        'hierarchical_permissions' => env('WORKOS_HIERARCHICAL_PERMISSIONS', true),
        'role_inheritance' => env('WORKOS_ROLE_INHERITANCE', true),
        'organization_scoped' => env('WORKOS_ORG_SCOPED_PERMISSIONS', true),
        'default_permissions' => explode(',', env('WORKOS_DEFAULT_PERMISSIONS', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Configure logging behavior for WorkOS operations including
    | authentication events and API calls.
    |
    */

    'logging' => [
        'enabled' => env('WORKOS_LOGGING_ENABLED', true),
        'channel' => env('WORKOS_LOG_CHANNEL', null), // Uses default log channel
        'level' => env('WORKOS_LOG_LEVEL', 'info'),
        'include_request_data' => env('WORKOS_LOG_INCLUDE_REQUEST_DATA', false),
        'include_response_data' => env('WORKOS_LOG_INCLUDE_RESPONSE_DATA', false),
        'events' => [
            'authentication' => env('WORKOS_LOG_AUTH_EVENTS', true),
            'api_calls' => env('WORKOS_LOG_API_CALLS', false),
            'errors' => env('WORKOS_LOG_ERRORS', true),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | Additional security settings including CSRF protection and
    | input validation.
    |
    */

    'security' => [
        'csrf_protection' => env('WORKOS_CSRF_PROTECTION', true),
        'state_parameter_length' => (int) env('WORKOS_STATE_PARAMETER_LENGTH', 32),
        'validate_state' => env('WORKOS_VALIDATE_STATE', true),
        'require_https' => env('WORKOS_REQUIRE_HTTPS', null), // Auto-detect in production
        'input_sanitization' => env('WORKOS_INPUT_SANITIZATION', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Development and Testing Configuration
    |--------------------------------------------------------------------------
    |
    | Settings specifically for development and testing environments.
    |
    */

    'development' => [
        'debug_mode' => env('WORKOS_DEBUG_MODE', env('APP_DEBUG', false)),
        'mock_api_responses' => env('WORKOS_MOCK_API_RESPONSES', false),
        'bypass_signature_verification' => env('WORKOS_BYPASS_JWT_VERIFICATION', false),
        'test_user_data' => [
            'enabled' => env('WORKOS_TEST_USER_DATA_ENABLED', false),
            'default_user_id' => env('WORKOS_TEST_DEFAULT_USER_ID', 'user_test_123'),
            'default_organization_id' => env('WORKOS_TEST_DEFAULT_ORG_ID', 'org_test_123'),
        ],
    ],
];