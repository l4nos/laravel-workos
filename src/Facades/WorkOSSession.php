<?php

declare(strict_types=1);

namespace LaravelWorkOS\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * WorkOSSession Facade
 * 
 * Provides convenient static access to WorkOS session management services.
 * 
 * @method static array createSession(array $sessionData)
 * @method static array validateSession(string $sessionId)
 * @method static array refreshSession(string $sessionId)
 * @method static void terminateSession(string $sessionId)
 * @method static void storeSession(string $sealedSession)
 * @method static string|null getSessionId()
 * @method static array|null getSessionData(string $sessionId)
 * @method static string getLogoutUrl(string $sessionId = null)
 * @method static bool isSessionValid(string $sessionId)
 * @method static bool isSessionExpired(string $sessionId)
 * @method static int getSessionTtl(string $sessionId)
 * @method static void clearUserCache(string $userId)
 * @method static void clearUserPermissionsCache(string $userId)
 * @method static void clearAllUserCache(string $userId)
 * @method static array getActiveSessions(string $userId)
 * @method static void terminateAllUserSessions(string $userId)
 * @method static array getSessionMetadata(string $sessionId)
 * @method static void updateSessionMetadata(string $sessionId, array $metadata)
 * @method static array encryptSessionData(array $data)
 * @method static array decryptSessionData(string $encryptedData)
 * 
 * @see \LaravelWorkOS\Services\SessionService
 */
class WorkOSSession extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'workos.session';
    }
}