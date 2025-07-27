<?php

declare(strict_types=1);

namespace LaravelWorkOS\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use LaravelWorkOS\WorkOSServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * Base test case for the Laravel WorkOS package.
 * 
 * This class provides common setup and utilities for all tests.
 */
abstract class TestCase extends Orchestra
{
    /**
     * Setup the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpWorkOSConfiguration();
        $this->setUpMockResponses();
    }

    /**
     * Get package providers.
     *
     * @param Application $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            WorkOSServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param Application $app
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        // Setup test configuration
        Config::set('workos.api_key', 'sk_test_123456789');
        Config::set('workos.client_id', 'client_test_123456789');
        Config::set('workos.cookie_password', 'test-cookie-password-32-chars12');
        
        Config::set('workos.cache.enabled', true);
        Config::set('workos.cache.prefix', 'workos_test');
        Config::set('workos.cache.ttl.user', 3600);
        Config::set('workos.cache.ttl.permissions', 1800);
        
        Config::set('workos.guards.session.driver', 'workos-session');
        Config::set('workos.guards.session.provider', 'workos');
        Config::set('workos.guards.api.driver', 'workos-api');
        Config::set('workos.guards.api.provider', 'workos');
        Config::set('workos.guards.server.driver', 'workos-server');
        Config::set('workos.guards.server.provider', 'workos');
        
        Config::set('workos.redirects.login', '/login');
        Config::set('workos.redirects.callback', '/auth/callback');
        Config::set('workos.redirects.logout', '/');
        Config::set('workos.redirects.success', '/dashboard');
    }

    /**
     * Setup WorkOS configuration for testing.
     *
     * @return void
     */
    protected function setUpWorkOSConfiguration(): void
    {
        config([
            'auth.guards.workos-session' => [
                'driver' => 'workos-session',
                'provider' => 'workos',
            ],
            'auth.guards.workos-api' => [
                'driver' => 'workos-api',
                'provider' => 'workos',
            ],
            'auth.guards.workos-server' => [
                'driver' => 'workos-server',
                'provider' => 'workos',
            ],
            'auth.providers.workos' => [
                'driver' => 'workos',
            ],
        ]);
    }

    /**
     * Setup mock responses for WorkOS API calls.
     *
     * @return void
     */
    protected function setUpMockResponses(): void
    {
        // This would typically set up HTTP mocks for WorkOS API calls
        // For now, we'll leave this as a placeholder for specific test implementations
    }

    /**
     * Create a mock WorkOS user.
     *
     * @param array $attributes
     * @return array
     */
    protected function createMockWorkOSUser(array $attributes = []): array
    {
        return array_merge([
            'id' => 'user_test_123456789',
            'email' => 'test@example.com',
            'first_name' => 'Test',
            'last_name' => 'User',
            'created_at' => '2023-01-01T00:00:00.000Z',
            'updated_at' => '2023-01-01T00:00:00.000Z',
            'organization_memberships' => [
                [
                    'id' => 'org_membership_123',
                    'organization' => [
                        'id' => 'org_test_123456789',
                        'name' => 'Test Organization',
                        'domains' => [
                            ['domain' => 'example.com']
                        ]
                    ],
                    'permissions' => ['read', 'write'],
                    'role' => ['name' => 'admin'],
                ]
            ]
        ], $attributes);
    }

    /**
     * Create a mock WorkOS organization.
     *
     * @param array $attributes
     * @return array
     */
    protected function createMockWorkOSOrganization(array $attributes = []): array
    {
        return array_merge([
            'id' => 'org_test_123456789',
            'name' => 'Test Organization',
            'domains' => [
                [
                    'id' => 'domain_123',
                    'domain' => 'example.com',
                    'state' => 'verified'
                ]
            ],
            'created_at' => '2023-01-01T00:00:00.000Z',
            'updated_at' => '2023-01-01T00:00:00.000Z',
        ], $attributes);
    }

    /**
     * Create a mock JWT token.
     *
     * @param array $payload
     * @return string
     */
    protected function createMockJWT(array $payload = []): string
    {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'RS256']);
        $defaultPayload = [
            'iss' => 'https://api.workos.com',
            'sub' => 'user_test_123456789',
            'aud' => 'client_test_123456789',
            'exp' => time() + 3600,
            'iat' => time(),
            'organization_id' => 'org_test_123456789',
            'permissions' => ['read', 'write'],
            'role' => 'admin'
        ];
        
        $mergedPayload = array_merge($defaultPayload, $payload);
        $payloadJson = json_encode($mergedPayload);
        
        // Create a mock JWT (not cryptographically secure, just for testing)
        $headerEncoded = base64url_encode($header);
        $payloadEncoded = base64url_encode($payloadJson);
        $signature = base64url_encode('mock_signature');
        
        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
    }

    /**
     * Assert that a user has the expected WorkOS structure.
     *
     * @param mixed $user
     * @return void
     */
    protected function assertWorkOSUserStructure($user): void
    {
        $this->assertInstanceOf(\LaravelWorkOS\Auth\Models\WorkOSUser::class, $user);
        $this->assertNotEmpty($user->getWorkOSId());
        $this->assertNotEmpty($user->getEmail());
        $this->assertTrue(method_exists($user, 'getPermissions'));
        $this->assertTrue(method_exists($user, 'getRoles'));
        $this->assertTrue(method_exists($user, 'hasPermission'));
        $this->assertTrue(method_exists($user, 'hasRole'));
    }

    /**
     * Mock a WorkOS API response.
     *
     * @param string $method
     * @param string $endpoint
     * @param array $response
     * @return void
     */
    protected function mockWorkOSApiResponse(string $method, string $endpoint, array $response): void
    {
        // This would typically use HTTP mocking libraries like Guzzle Mock Handler
        // For now, this is a placeholder for specific test implementations
    }
}

/**
 * Base64 URL encode function for JWT creation.
 *
 * @param string $data
 * @return string
 */
function base64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}