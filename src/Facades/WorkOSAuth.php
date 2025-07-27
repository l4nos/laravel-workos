<?php

declare(strict_types=1);

namespace LaravelWorkOS\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * WorkOSAuth Facade
 * 
 * Provides convenient static access to AuthKit authentication services.
 * 
 * @method static array generateAuthorizationUrl(array $options = [])
 * @method static array handleCallback(string $code, string $state)
 * @method static string getLoginUrl(array $options = [])
 * @method static string getLogoutUrl(string $sessionId = null)
 * @method static array authenticateUser(string $code)
 * @method static bool validateSession(string $sessionId)
 * @method static void refreshSession(string $sessionId)
 * @method static void terminateSession(string $sessionId)
 * @method static array getSessionDetails(string $sessionId)
 * @method static string generateStateParameter()
 * @method static bool verifyStateParameter(string $state)
 * @method static array getOrganizationLoginUrl(string $organizationId, array $options = [])
 * @method static array switchOrganization(string $organizationId)
 * 
 * @see \LaravelWorkOS\Services\AuthKitService
 */
class WorkOSAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'workos.auth';
    }
}