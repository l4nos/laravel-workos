<?php

declare(strict_types=1);

namespace LaravelWorkOS\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * WorkOS Facade
 * 
 * Provides convenient static access to the core WorkOS service.
 * 
 * @method static \WorkOS\UserManagement getUserManagement()
 * @method static \WorkOS\Organizations getOrganizations()
 * @method static \WorkOS\DirectorySync getDirectorySync()
 * @method static \WorkOS\SSO getSso()
 * @method static \WorkOS\Events getEvents()
 * @method static \WorkOS\Webhooks getWebhooks()
 * @method static \WorkOS\MFA getMfa()
 * @method static \WorkOS\AuditLogs getAuditLogs()
 * @method static array listUsers(array $options = [])
 * @method static array getUser(string $userId)
 * @method static array createUser(array $userData)
 * @method static array updateUser(string $userId, array $userData)
 * @method static void deleteUser(string $userId)
 * @method static array listOrganizations(array $options = [])
 * @method static array getOrganization(string $organizationId)
 * @method static array createOrganization(array $organizationData)
 * @method static array updateOrganization(string $organizationId, array $organizationData)
 * @method static void deleteOrganization(string $organizationId)
 * @method static array listOrganizationUsers(string $organizationId, array $options = [])
 * @method static array createOrganizationMembership(string $organizationId, array $membershipData)
 * @method static void deleteOrganizationMembership(string $organizationId, string $userId)
 * @method static bool isHealthy()
 * @method static array getApiInfo()
 * 
 * @see \LaravelWorkOS\Services\WorkOSService
 */
class WorkOS extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'workos';
    }
}