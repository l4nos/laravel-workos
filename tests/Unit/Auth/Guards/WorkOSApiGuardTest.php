<?php

declare(strict_types=1);

namespace LaravelWorkOS\Tests\Unit\Auth\Guards;

use LaravelWorkOS\Auth\Guards\WorkOSApiGuard;
use LaravelWorkOS\Auth\Providers\WorkOSUserProvider;
use LaravelWorkOS\Tests\TestCase;
use Illuminate\Http\Request;
use Mockery;

/**
 * Test the WorkOS API Guard functionality.
 */
class WorkOSApiGuardTest extends TestCase
{
    private WorkOSApiGuard $guard;
    private $mockProvider;
    private $mockRequest;
    private $mockWorkOS;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockProvider = Mockery::mock(WorkOSUserProvider::class);
        $this->mockRequest = Mockery::mock(Request::class);
        $this->mockWorkOS = Mockery::mock(\LaravelWorkOS\Services\WorkOSService::class);

        $this->guard = new WorkOSApiGuard(
            $this->mockProvider,
            $this->mockRequest,
            $this->mockWorkOS,
            config('workos')
        );
    }

    /** @test */
    public function it_can_extract_bearer_token_from_authorization_header(): void
    {
        $token = 'test-jwt-token';
        
        $this->mockRequest
            ->shouldReceive('bearerToken')
            ->once()
            ->andReturn($token);

        $this->mockProvider
            ->shouldReceive('validateToken')
            ->with($token)
            ->once()
            ->andReturn($this->createMockWorkOSUser());

        $user = $this->guard->user();

        $this->assertWorkOSUserStructure($user);
        $this->assertEquals('user_test_123456789', $user->getWorkOSId());
    }

    /** @test */
    public function it_returns_null_when_no_token_provided(): void
    {
        $this->mockRequest
            ->shouldReceive('bearerToken')
            ->once()
            ->andReturn(null);

        $user = $this->guard->user();

        $this->assertNull($user);
    }

    /** @test */
    public function it_returns_null_when_token_validation_fails(): void
    {
        $token = 'invalid-token';
        
        $this->mockRequest
            ->shouldReceive('bearerToken')
            ->once()
            ->andReturn($token);

        $this->mockProvider
            ->shouldReceive('validateToken')
            ->with($token)
            ->once()
            ->andReturn(null);

        $user = $this->guard->user();

        $this->assertNull($user);
    }

    /** @test */
    public function it_validates_credentials(): void
    {
        $credentials = ['token' => 'test-jwt-token'];

        $this->mockProvider
            ->shouldReceive('validateCredentials')
            ->with(null, $credentials)
            ->once()
            ->andReturn(true);

        $result = $this->guard->validate($credentials);

        $this->assertTrue($result);
    }

    /** @test */
    public function it_fails_validation_with_invalid_credentials(): void
    {
        $credentials = ['token' => 'invalid-token'];

        $this->mockProvider
            ->shouldReceive('validateCredentials')
            ->with(null, $credentials)
            ->once()
            ->andReturn(false);

        $result = $this->guard->validate($credentials);

        $this->assertFalse($result);
    }

    /** @test */
    public function it_caches_authenticated_user(): void
    {
        $token = 'test-jwt-token';
        $mockUser = $this->createMockWorkOSUser();
        
        $this->mockRequest
            ->shouldReceive('bearerToken')
            ->once()
            ->andReturn($token);

        $this->mockProvider
            ->shouldReceive('validateToken')
            ->with($token)
            ->once()
            ->andReturn($mockUser);

        // First call should hit the provider
        $user1 = $this->guard->user();
        
        // Second call should return cached user (no additional provider call)
        $user2 = $this->guard->user();

        $this->assertSame($user1, $user2);
        $this->assertWorkOSUserStructure($user1);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}