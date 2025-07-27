<?php

declare(strict_types=1);

namespace LaravelWorkOS\Console\Commands;

use Illuminate\Console\Command;
use LaravelWorkOS\Facades\WorkOS;
use LaravelWorkOS\Facades\WorkOSAuth;

/**
 * TestConnectionCommand tests WorkOS API connectivity and configuration.
 * 
 * This command helps developers verify their WorkOS setup by:
 * - Testing API key authentication
 * - Validating configuration
 * - Checking service connectivity
 * - Providing diagnostic information
 */
class TestConnectionCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'workos:test 
                            {--detailed : Show detailed diagnostic information}
                            {--user-id= : Test user retrieval with specific user ID}
                            {--organization-id= : Test organization retrieval with specific organization ID}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test WorkOS API connectivity and configuration';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info('🔍 Testing WorkOS Connection...');
        $this->newLine();

        $allTestsPassed = true;

        // Test 1: Configuration validation
        if (!$this->testConfiguration()) {
            $allTestsPassed = false;
        }

        // Test 2: API connectivity
        if (!$this->testApiConnectivity()) {
            $allTestsPassed = false;
        }

        // Test 3: Service availability
        if (!$this->testServiceAvailability()) {
            $allTestsPassed = false;
        }

        // Test 4: Authentication flow (if detailed)
        if ($this->option('detailed')) {
            if (!$this->testAuthenticationFlow()) {
                $allTestsPassed = false;
            }
        }

        // Test 5: Specific user test (if provided)
        if ($this->option('user-id')) {
            if (!$this->testUserRetrieval($this->option('user-id'))) {
                $allTestsPassed = false;
            }
        }

        // Test 6: Specific organization test (if provided)
        if ($this->option('organization-id')) {
            if (!$this->testOrganizationRetrieval($this->option('organization-id'))) {
                $allTestsPassed = false;
            }
        }

        $this->newLine();
        
        if ($allTestsPassed) {
            $this->info('✅ All tests passed! WorkOS is configured correctly.');
            return self::SUCCESS;
        } else {
            $this->error('❌ Some tests failed. Please check your WorkOS configuration.');
            return self::FAILURE;
        }
    }

    /**
     * Test configuration validation.
     *
     * @return bool
     */
    protected function testConfiguration(): bool
    {
        $this->line('🔧 Testing Configuration...');
        
        $errors = [];
        
        // Check required environment variables
        $requiredVars = [
            'WORKOS_API_KEY' => 'API Key',
            'WORKOS_CLIENT_ID' => 'Client ID',
            'WORKOS_COOKIE_PASSWORD' => 'Cookie Password',
        ];

        foreach ($requiredVars as $var => $name) {
            $value = env($var);
            if (!$value) {
                $errors[] = "{$name} ({$var}) is not configured";
            } elseif ($var === 'WORKOS_API_KEY' && !str_starts_with($value, 'sk_')) {
                $errors[] = "{$name} should start with 'sk_'";
            } elseif ($var === 'WORKOS_CLIENT_ID' && !str_starts_with($value, 'client_')) {
                $errors[] = "{$name} should start with 'client_'";
            } elseif ($var === 'WORKOS_COOKIE_PASSWORD' && strlen($value) !== 32) {
                $errors[] = "{$name} must be exactly 32 characters long";
            }
        }

        // Check configuration file
        if (!config('workos')) {
            $errors[] = 'WorkOS configuration file not found or invalid';
        }

        if (empty($errors)) {
            $this->info('  ✅ Configuration is valid');
            return true;
        } else {
            $this->error('  ❌ Configuration errors:');
            foreach ($errors as $error) {
                $this->error("     • {$error}");
            }
            return false;
        }
    }

    /**
     * Test API connectivity.
     *
     * @return bool
     */
    protected function testApiConnectivity(): bool
    {
        $this->line('🌐 Testing API Connectivity...');

        try {
            // Test basic API connection - try to get organization info
            $organizations = WorkOS::getOrganizations()->listOrganizations([
                'limit' => 1
            ]);

            $this->info('  ✅ API connection successful');
            
            if ($this->option('detailed')) {
                $this->line("     API Response Status: OK");
                $this->line("     Organizations Available: " . count($organizations['data'] ?? []));
            }
            
            return true;

        } catch (\Exception $e) {
            $this->error('  ❌ API connection failed');
            $this->error("     Error: {$e->getMessage()}");
            
            if ($this->option('detailed')) {
                $this->error("     Error Type: " . get_class($e));
                $this->error("     Error Code: " . $e->getCode());
            }
            
            return false;
        }
    }

    /**
     * Test service availability.
     *
     * @return bool
     */
    protected function testServiceAvailability(): bool
    {
        $this->line('🔧 Testing Service Availability...');

        $services = [
            'User Management' => 'getUserManagement',
            'Organizations' => 'getOrganizations',
            'SSO' => 'getSso',
            'Directory Sync' => 'getDirectorySync',
        ];

        $allAvailable = true;

        foreach ($services as $name => $method) {
            try {
                $service = WorkOS::$method();
                $this->info("  ✅ {$name} service available");
            } catch (\Exception $e) {
                $this->error("  ❌ {$name} service unavailable: {$e->getMessage()}");
                $allAvailable = false;
            }
        }

        return $allAvailable;
    }

    /**
     * Test authentication flow.
     *
     * @return bool
     */
    protected function testAuthenticationFlow(): bool
    {
        $this->line('🔐 Testing Authentication Flow...');

        try {
            // Test authorization URL generation
            $authUrl = WorkOSAuth::generateAuthorizationUrl([
                'redirect_uri' => url('/auth/callback'),
            ]);

            if (!empty($authUrl['url']) && filter_var($authUrl['url'], FILTER_VALIDATE_URL)) {
                $this->info('  ✅ Authorization URL generation successful');
                
                if ($this->option('detailed')) {
                    $this->line("     Auth URL: {$authUrl['url']}");
                    $this->line("     State Parameter: " . ($authUrl['state'] ?? 'Generated'));
                }
            } else {
                $this->error('  ❌ Invalid authorization URL generated');
                return false;
            }

            return true;

        } catch (\Exception $e) {
            $this->error('  ❌ Authentication flow test failed');
            $this->error("     Error: {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Test user retrieval.
     *
     * @param string $userId
     * @return bool
     */
    protected function testUserRetrieval(string $userId): bool
    {
        $this->line("👤 Testing User Retrieval (ID: {$userId})...");

        try {
            $user = WorkOS::getUserManagement()->getUser($userId);

            $this->info('  ✅ User retrieval successful');
            
            if ($this->option('detailed')) {
                $this->line("     User ID: {$user['id']}");
                $this->line("     Email: {$user['email']}");
                $this->line("     Name: " . ($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
                $this->line("     Organizations: " . count($user['organization_memberships'] ?? []));
            }

            return true;

        } catch (\Exception $e) {
            $this->error('  ❌ User retrieval failed');
            $this->error("     Error: {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Test organization retrieval.
     *
     * @param string $organizationId
     * @return bool
     */
    protected function testOrganizationRetrieval(string $organizationId): bool
    {
        $this->line("🏢 Testing Organization Retrieval (ID: {$organizationId})...");

        try {
            $organization = WorkOS::getOrganizations()->getOrganization($organizationId);

            $this->info('  ✅ Organization retrieval successful');
            
            if ($this->option('detailed')) {
                $this->line("     Organization ID: {$organization['id']}");
                $this->line("     Name: {$organization['name']}");
                $this->line("     Domains: " . implode(', ', array_column($organization['domains'] ?? [], 'domain')));
            }

            return true;

        } catch (\Exception $e) {
            $this->error('  ❌ Organization retrieval failed');
            $this->error("     Error: {$e->getMessage()}");
            return false;
        }
    }
}