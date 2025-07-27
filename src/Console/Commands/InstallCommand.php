<?php

declare(strict_types=1);

namespace LaravelWorkOS\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

/**
 * InstallCommand handles package installation and setup.
 * 
 * This command helps developers set up the WorkOS package by:
 * - Publishing configuration files
 * - Providing environment variable setup guidance
 * - Validating the installation
 */
class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'workos:install 
                            {--force : Overwrite existing configuration files}
                            {--config-only : Only publish configuration files}
                            {--verify : Verify installation after setup}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure the Laravel WorkOS package';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info('🚀 Installing Laravel WorkOS Package...');
        $this->newLine();

        // Step 1: Publish configuration
        if (!$this->publishConfiguration()) {
            return self::FAILURE;
        }

        // Step 2: Setup environment variables (unless config-only)
        if (!$this->option('config-only')) {
            $this->setupEnvironmentVariables();
        }

        // Step 3: Display next steps
        $this->displayNextSteps();

        // Step 4: Verify installation if requested
        if ($this->option('verify')) {
            return $this->verifyInstallation();
        }

        $this->newLine();
        $this->info('✅ Laravel WorkOS package installed successfully!');
        
        return self::SUCCESS;
    }

    /**
     * Publish the configuration files.
     *
     * @return bool
     */
    protected function publishConfiguration(): bool
    {
        $this->info('📋 Publishing configuration files...');

        $configPath = config_path('workos.php');
        $force = $this->option('force');

        // Check if config already exists
        if (File::exists($configPath) && !$force) {
            if (!$this->confirm('Configuration file already exists. Do you want to overwrite it?', false)) {
                $this->warn('⚠️  Configuration publishing skipped.');
                return true;
            }
        }

        // Publish the configuration
        $exitCode = $this->call('vendor:publish', [
            '--provider' => 'LaravelWorkOS\\WorkOSServiceProvider',
            '--tag' => 'workos-config',
            '--force' => $force,
        ]);

        if ($exitCode !== 0) {
            $this->error('❌ Failed to publish configuration files.');
            return false;
        }

        $this->info('✅ Configuration files published successfully.');
        return true;
    }

    /**
     * Setup environment variables.
     *
     * @return void
     */
    protected function setupEnvironmentVariables(): void
    {
        $this->info('🔧 Setting up environment variables...');
        $this->newLine();

        $envPath = base_path('.env');
        $envContent = File::exists($envPath) ? File::get($envPath) : '';

        // Define required environment variables
        $envVars = [
            'WORKOS_API_KEY' => [
                'description' => 'Your WorkOS API Key (starts with sk_)',
                'example' => 'sk_example_123456789',
                'required' => true,
            ],
            'WORKOS_CLIENT_ID' => [
                'description' => 'Your WorkOS Client ID (starts with client_)',
                'example' => 'client_123456789',
                'required' => true,
            ],
            'WORKOS_COOKIE_PASSWORD' => [
                'description' => '32-character password for session encryption',
                'example' => Str::random(32),
                'required' => true,
            ],
            'WORKOS_REDIRECT_URI' => [
                'description' => 'OAuth callback URL for your application',
                'example' => url('/auth/callback'),
                'required' => false,
            ],
        ];

        $toAdd = [];

        foreach ($envVars as $key => $config) {
            if (!str_contains($envContent, $key . '=')) {
                $toAdd[$key] = $config;
            }
        }

        if (empty($toAdd)) {
            $this->info('✅ All required environment variables are already configured.');
            return;
        }

        // Display environment variables to add
        $this->warn('⚠️  The following environment variables need to be configured:');
        $this->newLine();

        $envLines = [];
        foreach ($toAdd as $key => $config) {
            $required = $config['required'] ? ' (Required)' : ' (Optional)';
            $this->line("<comment>{$key}</comment>{$required}");
            $this->line("  Description: {$config['description']}");
            $this->line("  Example: <info>{$config['example']}</info>");
            $this->newLine();

            $envLines[] = "# {$config['description']}";
            $envLines[] = "{$key}={$config['example']}";
            $envLines[] = "";
        }

        // Ask if user wants to add them automatically
        if ($this->confirm('Would you like to add these to your .env file automatically?', true)) {
            $envContent .= "\n# WorkOS Configuration\n" . implode("\n", $envLines);
            File::put($envPath, $envContent);
            $this->info('✅ Environment variables added to .env file.');
            $this->warn('⚠️  Please update the example values with your actual WorkOS credentials.');
        } else {
            $this->info('📝 Please manually add these environment variables to your .env file.');
        }
    }

    /**
     * Display next steps for the user.
     *
     * @return void
     */
    protected function displayNextSteps(): void
    {
        $this->newLine();
        $this->info('🎯 Next Steps:');
        $this->newLine();

        $steps = [
            '1. Configure your WorkOS credentials in .env file',
            '2. Add WorkOS guards and provider to config/auth.php',
            '3. Run "php artisan workos:test" to verify your connection',
            '4. Set up your routes using WorkOS authentication guards',
            '5. Configure your WorkOS application redirect URIs',
        ];

        foreach ($steps as $step) {
            $this->line("   {$step}");
        }

        $this->newLine();
        $this->info('📚 Documentation: https://github.com/your-org/laravel-workos');
    }

    /**
     * Verify the installation.
     *
     * @return int
     */
    protected function verifyInstallation(): int
    {
        $this->newLine();
        $this->info('🔍 Verifying installation...');

        $errors = [];

        // Check configuration file
        if (!File::exists(config_path('workos.php'))) {
            $errors[] = 'Configuration file not found at config/workos.php';
        }

        // Check environment variables
        $requiredEnvVars = ['WORKOS_API_KEY', 'WORKOS_CLIENT_ID', 'WORKOS_COOKIE_PASSWORD'];
        foreach ($requiredEnvVars as $var) {
            if (!env($var)) {
                $errors[] = "Environment variable {$var} is not set";
            }
        }

        // Check API key format
        $apiKey = env('WORKOS_API_KEY');
        if ($apiKey && !str_starts_with($apiKey, 'sk_')) {
            $errors[] = 'WORKOS_API_KEY should start with "sk_"';
        }

        // Check client ID format
        $clientId = env('WORKOS_CLIENT_ID');
        if ($clientId && !str_starts_with($clientId, 'client_')) {
            $errors[] = 'WORKOS_CLIENT_ID should start with "client_"';
        }

        // Check cookie password length
        $cookiePassword = env('WORKOS_COOKIE_PASSWORD');
        if ($cookiePassword && strlen($cookiePassword) !== 32) {
            $errors[] = 'WORKOS_COOKIE_PASSWORD must be exactly 32 characters long';
        }

        if (empty($errors)) {
            $this->info('✅ Installation verification passed!');
            return self::SUCCESS;
        } else {
            $this->error('❌ Installation verification failed:');
            foreach ($errors as $error) {
                $this->error("   • {$error}");
            }
            return self::FAILURE;
        }
    }
}