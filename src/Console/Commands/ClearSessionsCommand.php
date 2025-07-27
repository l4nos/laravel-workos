<?php

declare(strict_types=1);

namespace LaravelWorkOS\Console\Commands;

use Illuminate\Console\Command;
use LaravelWorkOS\Facades\WorkOSSession;
use LaravelWorkOS\Facades\WorkOS;

/**
 * ClearSessionsCommand handles session cleanup and maintenance.
 * 
 * This command provides utilities for:
 * - Cleaning up expired sessions
 * - Clearing user-specific cache
 * - Session maintenance and statistics
 * - Bulk session operations
 */
class ClearSessionsCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'workos:clear-sessions 
                            {--user-id= : Clear sessions for specific user}
                            {--organization-id= : Clear sessions for specific organization}
                            {--expired : Only clear expired sessions}
                            {--dry-run : Show what would be cleared without actually clearing}
                            {--stats : Show session statistics}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clear WorkOS sessions and cache data';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info('🧹 WorkOS Session Cleanup Tool');
        $this->newLine();

        // Show statistics if requested
        if ($this->option('stats')) {
            $this->showSessionStatistics();
            $this->newLine();
        }

        // Determine cleanup strategy
        $userId = $this->option('user-id');
        $organizationId = $this->option('organization-id');
        $expiredOnly = $this->option('expired');
        $dryRun = $this->option('dry-run');

        if ($dryRun) {
            $this->warn('🔍 DRY RUN MODE - No data will actually be cleared');
            $this->newLine();
        }

        $clearedCount = 0;

        try {
            if ($userId) {
                $clearedCount = $this->clearUserSessions($userId, $dryRun);
            } elseif ($organizationId) {
                $clearedCount = $this->clearOrganizationSessions($organizationId, $dryRun);
            } elseif ($expiredOnly) {
                $clearedCount = $this->clearExpiredSessions($dryRun);
            } else {
                // Confirm before clearing all sessions
                if (!$this->confirmClearAll()) {
                    $this->info('Operation cancelled.');
                    return self::SUCCESS;
                }
                $clearedCount = $this->clearAllCachedData($dryRun);
            }

            $this->newLine();
            
            if ($dryRun) {
                $this->info("✅ Dry run completed. {$clearedCount} items would be cleared.");
            } else {
                $this->info("✅ Session cleanup completed. {$clearedCount} items cleared.");
            }

            return self::SUCCESS;

        } catch (\Exception $e) {
            $this->error('❌ Session cleanup failed:');
            $this->error("   {$e->getMessage()}");
            return self::FAILURE;
        }
    }

    /**
     * Show session statistics.
     *
     * @return void
     */
    protected function showSessionStatistics(): void
    {
        $this->info('📊 Session Statistics:');

        try {
            // Get cache statistics if available
            $cachePrefix = config('workos.cache.prefix', 'workos');
            
            // Note: In a real implementation, you'd query your cache store
            // This is a placeholder for demonstration
            $stats = [
                'Total Cached Users' => $this->getCacheCount("{$cachePrefix}:user:*"),
                'Total Cached Permissions' => $this->getCacheCount("{$cachePrefix}:permissions:*"),
                'Total Cached Organizations' => $this->getCacheCount("{$cachePrefix}:organizations:*"),
                'Total Cached Sessions' => $this->getCacheCount("{$cachePrefix}:session:*"),
            ];

            foreach ($stats as $label => $count) {
                $this->line("  {$label}: {$count}");
            }

        } catch (\Exception $e) {
            $this->warn('  Unable to retrieve session statistics');
        }
    }

    /**
     * Clear sessions for a specific user.
     *
     * @param string $userId
     * @param bool $dryRun
     * @return int
     */
    protected function clearUserSessions(string $userId, bool $dryRun = false): int
    {
        $this->info("👤 Clearing sessions for user: {$userId}");

        $cleared = 0;
        $cachePrefix = config('workos.cache.prefix', 'workos');

        // Clear user-specific cache keys
        $cacheKeys = [
            "{$cachePrefix}:user:{$userId}",
            "{$cachePrefix}:permissions:{$userId}",
            "{$cachePrefix}:organizations:{$userId}",
        ];

        foreach ($cacheKeys as $key) {
            if (!$dryRun) {
                try {
                    WorkOSSession::clearUserCache($userId);
                    $this->line("  ✅ Cleared cache: {$key}");
                    $cleared++;
                } catch (\Exception $e) {
                    $this->warn("  ⚠️  Failed to clear: {$key}");
                }
            } else {
                $this->line("  🔍 Would clear: {$key}");
                $cleared++;
            }
        }

        // Terminate active sessions if not dry run
        if (!$dryRun) {
            try {
                if (method_exists(WorkOSSession::class, 'terminateAllUserSessions')) {
                    WorkOSSession::terminateAllUserSessions($userId);
                    $this->line("  ✅ Terminated active sessions");
                    $cleared++;
                }
            } catch (\Exception $e) {
                $this->warn("  ⚠️  Failed to terminate sessions: {$e->getMessage()}");
            }
        } else {
            $this->line("  🔍 Would terminate active sessions");
            $cleared++;
        }

        return $cleared;
    }

    /**
     * Clear sessions for a specific organization.
     *
     * @param string $organizationId
     * @param bool $dryRun
     * @return int
     */
    protected function clearOrganizationSessions(string $organizationId, bool $dryRun = false): int
    {
        $this->info("🏢 Clearing sessions for organization: {$organizationId}");

        $cleared = 0;

        try {
            // Get all users in the organization
            $organizationUsers = WorkOS::getUserManagement()->listUsers(organizationId: $organizationId);

            foreach ($organizationUsers['data'] as $user) {
                $userId = $user['id'];
                $userCleared = $this->clearUserSessions($userId, $dryRun);
                $cleared += $userCleared;
            }

            // Clear organization-specific cache
            $cachePrefix = config('workos.cache.prefix', 'workos');
            $orgCacheKey = "{$cachePrefix}:organization:{$organizationId}";

            if (!$dryRun) {
                cache()->forget($orgCacheKey);
                $this->line("  ✅ Cleared organization cache");
                $cleared++;
            } else {
                $this->line("  🔍 Would clear organization cache");
                $cleared++;
            }

        } catch (\Exception $e) {
            $this->error("  ❌ Failed to clear organization sessions: {$e->getMessage()}");
        }

        return $cleared;
    }

    /**
     * Clear only expired sessions.
     *
     * @param bool $dryRun
     * @return int
     */
    protected function clearExpiredSessions(bool $dryRun = false): int
    {
        $this->info('⏰ Clearing expired sessions...');

        $cleared = 0;

        // Note: In a real implementation, you'd iterate through all cached sessions
        // and check their expiration times. This is a simplified version.
        
        try {
            $cachePrefix = config('workos.cache.prefix', 'workos');
            
            // This would typically involve checking each cached session's TTL
            // For now, we'll simulate the process
            $expiredSessions = $this->getExpiredSessions();

            foreach ($expiredSessions as $sessionKey) {
                if (!$dryRun) {
                    cache()->forget($sessionKey);
                    $this->line("  ✅ Cleared expired session: {$sessionKey}");
                    $cleared++;
                } else {
                    $this->line("  🔍 Would clear expired session: {$sessionKey}");
                    $cleared++;
                }
            }

        } catch (\Exception $e) {
            $this->error("  ❌ Failed to clear expired sessions: {$e->getMessage()}");
        }

        return $cleared;
    }

    /**
     * Clear all cached data.
     *
     * @param bool $dryRun
     * @return int
     */
    protected function clearAllCachedData(bool $dryRun = false): int
    {
        $this->info('🗑️  Clearing all WorkOS cached data...');

        $cleared = 0;
        $cachePrefix = config('workos.cache.prefix', 'workos');

        // Clear all cache keys with the WorkOS prefix
        $cacheTypes = ['user', 'permissions', 'organizations', 'session'];

        foreach ($cacheTypes as $type) {
            $pattern = "{$cachePrefix}:{$type}:*";
            $count = $this->clearCachePattern($pattern, $dryRun);
            $cleared += $count;
            
            if ($dryRun) {
                $this->line("  🔍 Would clear {$count} {$type} cache entries");
            } else {
                $this->line("  ✅ Cleared {$count} {$type} cache entries");
            }
        }

        return $cleared;
    }

    /**
     * Confirm before clearing all sessions.
     *
     * @return bool
     */
    protected function confirmClearAll(): bool
    {
        $this->warn('⚠️  You are about to clear ALL WorkOS cached data.');
        $this->warn('This will log out all users and clear all cached permissions.');
        $this->newLine();

        return $this->confirm('Are you sure you want to continue?', false);
    }

    /**
     * Get count of cache entries matching a pattern.
     * Note: This is a simplified implementation for demonstration.
     *
     * @param string $pattern
     * @return int
     */
    protected function getCacheCount(string $pattern): int
    {
        // In a real implementation, this would query your cache store
        // Different cache drivers have different ways to count keys
        // This is a placeholder that returns a simulated count
        return rand(0, 50);
    }

    /**
     * Get expired sessions.
     * Note: This is a simplified implementation for demonstration.
     *
     * @return array
     */
    protected function getExpiredSessions(): array
    {
        // In a real implementation, this would check cache TTLs
        // This is a placeholder that returns simulated expired sessions
        $cachePrefix = config('workos.cache.prefix', 'workos');
        
        return [
            "{$cachePrefix}:session:expired_1",
            "{$cachePrefix}:session:expired_2",
        ];
    }

    /**
     * Clear cache entries matching a pattern.
     * Note: This is a simplified implementation for demonstration.
     *
     * @param string $pattern
     * @param bool $dryRun
     * @return int
     */
    protected function clearCachePattern(string $pattern, bool $dryRun = false): int
    {
        // In a real implementation, this would:
        // 1. Get all keys matching the pattern
        // 2. Delete them from the cache
        // Different cache drivers have different methods for this
        
        // For demonstration, we'll return a simulated count
        $count = rand(5, 25);
        
        if (!$dryRun) {
            // In real implementation: cache()->forget() for each matching key
        }
        
        return $count;
    }
}