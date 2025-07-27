<?php

declare(strict_types=1);

namespace LaravelWorkOS;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use LaravelWorkOS\Auth\Guards\WorkOSApiGuard;
use LaravelWorkOS\Auth\Guards\WorkOSServerGuard;
use LaravelWorkOS\Auth\Guards\WorkOSSessionGuard;
use LaravelWorkOS\Auth\Providers\WorkOSUserProvider;
use LaravelWorkOS\Http\Middleware\WorkOSOrganization;
use LaravelWorkOS\Http\Middleware\WorkOSPermissions;
use LaravelWorkOS\Services\AuthKitService;
use LaravelWorkOS\Services\PermissionService;
use LaravelWorkOS\Services\SessionService;
use LaravelWorkOS\Services\WorkOSService;
use WorkOS\WorkOS;

class WorkOSServiceProvider extends ServiceProvider
{
    /**
     * All of the container bindings that should be registered.
     *
     * @var array<string, string>
     */
    public array $bindings = [
        'workos' => WorkOSService::class,
        'workos.auth' => AuthKitService::class,
        'workos.session' => SessionService::class,
        'workos.permissions' => PermissionService::class,
    ];

    /**
     * All of the container singletons that should be registered.
     *
     * @var array<string, string>
     */
    public array $singletons = [
        WorkOSService::class => WorkOSService::class,
        AuthKitService::class => AuthKitService::class,
        SessionService::class => SessionService::class,
        PermissionService::class => PermissionService::class,
    ];

    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/Config/workos.php',
            'workos'
        );

        $this->registerCoreServices();
        $this->registerAuthComponents();
        $this->registerCommands();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->bootConfiguration();
        $this->bootAuthSystem();
        $this->bootMiddleware();
        $this->bootRoutes();
        $this->bootViews();
        $this->bootValidation();
    }

    /**
     * Register core WorkOS services.
     */
    protected function registerCoreServices(): void
    {
        // Register the core WorkOS client
        $this->app->singleton(WorkOS::class, function ($app) {
            $config = $app['config']['workos'];
            
            WorkOS::setApiKey($config['api_key']);
            WorkOS::setClientId($config['client_id']);
            
            return new WorkOS();
        });

        // Register the main WorkOS service wrapper
        $this->app->singleton('workos', function ($app) {
            return new WorkOSService($app[WorkOS::class], $app['config']['workos']);
        });

        // Register AuthKit service
        $this->app->singleton('workos.auth', function ($app) {
            return new AuthKitService(
                $app['workos'],
                $app['config']['workos'],
                $app['session'],
                $app['request']
            );
        });

        // Register Session service
        $this->app->singleton('workos.session', function ($app) {
            return new SessionService(
                $app['workos'],
                $app['config']['workos'],
                $app['session'],
                $app['cookie']
            );
        });

        // Register Permission service
        $this->app->singleton('workos.permissions', function ($app) {
            return new PermissionService(
                $app['workos'],
                $app['config']['workos'],
                $app['cache']
            );
        });
    }

    /**
     * Register authentication components.
     */
    protected function registerAuthComponents(): void
    {
        // Register the WorkOS user provider
        Auth::provider('workos', function ($app, array $config) {
            return new WorkOSUserProvider(
                $app['workos'],
                $app['config']['workos'],
                $app['cache']
            );
        });

        // Register custom authentication guards
        Auth::extend('workos-api', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            
            return new WorkOSApiGuard(
                $provider,
                $app['request'],
                $app['workos'],
                $app['config']['workos']
            );
        });

        Auth::extend('workos-session', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            
            return new WorkOSSessionGuard(
                $provider,
                $app['session'],
                $app['request'],
                $app['workos.session'],
                $app['workos.auth']
            );
        });

        Auth::extend('workos-server', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            
            return new WorkOSServerGuard(
                $provider,
                $app['workos'],
                $app['config']['workos']
            );
        });
    }

    /**
     * Register console commands.
     */
    protected function registerCommands(): void
    {
        // TODO: Implement console commands
        // - InstallCommand for package installation
        // - TestConnectionCommand for WorkOS API testing
        // - ClearSessionsCommand for session cleanup
    }

    /**
     * Boot configuration publishing.
     */
    protected function bootConfiguration(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/Config/workos.php' => config_path('workos.php'),
            ], 'workos-config');

            $this->publishes([
                __DIR__.'/Config/workos.php' => config_path('workos.php'),
            ], 'workos');
        }
    }

    /**
     * Boot the authentication system integration.
     */
    protected function bootAuthSystem(): void
    {
        // Extend Laravel's auth configuration with WorkOS guards
        $this->extendAuthConfiguration();

        // Register auth events
        $this->registerAuthEvents();
    }

    /**
     * Extend Laravel's auth configuration with WorkOS guards.
     */
    protected function extendAuthConfiguration(): void
    {
        $config = $this->app['config'];
        $workosConfig = $config->get('workos', []);

        // Add WorkOS guards to auth configuration if they don't exist
        foreach ($workosConfig['guards'] ?? [] as $name => $guard) {
            $fullGuardName = "workos-{$name}";
            
            if (!$config->has("auth.guards.{$fullGuardName}")) {
                $config->set("auth.guards.{$fullGuardName}", $guard);
            }
        }

        // Add WorkOS user provider if it doesn't exist
        if (!$config->has('auth.providers.workos')) {
            $config->set('auth.providers.workos', [
                'driver' => 'workos',
            ]);
        }

        // Set default guard if specified
        $defaultGuard = $workosConfig['default_guard'] ?? null;
        if ($defaultGuard && !$config->has('auth.defaults.guard')) {
            $config->set('auth.defaults.guard', $defaultGuard);
        }
    }

    /**
     * Register authentication events.
     */
    protected function registerAuthEvents(): void
    {
        // Listen for authentication events to log and cache user data
        $this->app['events']->listen('auth.login', function ($event) {
            if (method_exists($event, 'user') && $event->user instanceof \LaravelWorkOS\Auth\Models\WorkOSUser) {
                $this->handleUserAuthenticated($event->user, $event->guard ?? 'unknown');
            }
        });

        $this->app['events']->listen('auth.logout', function ($event) {
            if (method_exists($event, 'user') && $event->user instanceof \LaravelWorkOS\Auth\Models\WorkOSUser) {
                $this->handleUserLoggedOut($event->user);
            }
        });
    }

    /**
     * Handle user authentication event.
     */
    protected function handleUserAuthenticated($user, string $guard): void
    {
        $config = $this->app['config']['workos'];
        
        if ($config['logging']['events']['authentication'] ?? true) {
            $this->app['log']->info('WorkOS user authenticated', [
                'user_id' => $user->getWorkOSId(),
                'guard' => $guard,
                'organization_id' => $user->getOrganizationId(),
                'timestamp' => now()->toISOString(),
            ]);
        }

        // Cache user data for performance
        if ($config['cache']['enabled'] ?? true) {
            $cacheKey = $config['cache']['prefix'].":user:{$user->getWorkOSId()}";
            $ttl = $config['cache']['ttl']['user'] ?? 3600;
            
            $this->app['cache']->put($cacheKey, $user->toArray(), $ttl);
        }
    }

    /**
     * Handle user logout event.
     */
    protected function handleUserLoggedOut($user): void
    {
        $config = $this->app['config']['workos'];
        
        if ($config['logging']['events']['authentication'] ?? true) {
            $this->app['log']->info('WorkOS user logged out', [
                'user_id' => $user->getWorkOSId(),
                'timestamp' => now()->toISOString(),
            ]);
        }

        // Clear user-specific cache
        if ($config['cache']['enabled'] ?? true) {
            $prefix = $config['cache']['prefix'];
            $userId = $user->getWorkOSId();
            
            $this->app['cache']->forget("{$prefix}:user:{$userId}");
            $this->app['cache']->forget("{$prefix}:permissions:{$userId}");
            $this->app['cache']->forget("{$prefix}:organizations:{$userId}");
        }
    }

    /**
     * Boot middleware registration.
     */
    protected function bootMiddleware(): void
    {
        $router = $this->app['router'];

        // Register WorkOS-specific middleware aliases
        // Note: Authentication is handled by Laravel's built-in 'auth' middleware
        // with developers configuring WorkOS guards in config/auth.php
        $router->aliasMiddleware('workos.permissions', WorkOSPermissions::class);
        $router->aliasMiddleware('workos.organization', WorkOSOrganization::class);

        // Register middleware groups for common WorkOS patterns
        $router->middlewareGroup('workos.protected', [
            'auth', // Use Laravel's auth middleware with developer's configured guard
            WorkOSPermissions::class,
        ]);

        $router->middlewareGroup('workos.organization', [
            'auth', // Use Laravel's auth middleware with developer's configured guard
            WorkOSOrganization::class,
        ]);
    }

    /**
     * Boot routes registration.
     */
    protected function bootRoutes(): void
    {
        if ($this->shouldRegisterRoutes()) {
            $this->loadRoutesFrom(__DIR__.'/Http/routes.php');
        }
    }

    /**
     * Boot views registration.
     */
    protected function bootViews(): void
    {
        $this->loadViewsFrom(__DIR__.'/Resources/views', 'workos');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/Resources/views' => resource_path('views/vendor/workos'),
            ], 'workos-views');

            $this->publishes([
                __DIR__.'/Resources/views' => resource_path('views/vendor/workos'),
            ], 'workos');
        }
    }

    /**
     * Boot validation rules.
     */
    protected function bootValidation(): void
    {
        $this->app['validator']->extend('workos_user', function ($attribute, $value, $parameters, $validator) {
            try {
                $provider = Auth::createUserProvider(['driver' => 'workos']);
                return $provider->retrieveById($value) !== null;
            } catch (\Exception) {
                return false;
            }
        });

        $this->app['validator']->extend('workos_organization', function ($attribute, $value, $parameters, $validator) {
            try {
                $workos = $this->app['workos'];
                $organization = $workos->getOrganizations()->getOrganization($value);
                return $organization !== null;
            } catch (\Exception) {
                return false;
            }
        });
    }

    /**
     * Determine if routes should be registered.
     */
    protected function shouldRegisterRoutes(): bool
    {
        $config = $this->app['config']['workos'];
        
        // Don't register routes if explicitly disabled
        if (isset($config['register_routes']) && !$config['register_routes']) {
            return false;
        }

        // Don't register routes in console unless testing
        if ($this->app->runningInConsole() && !$this->app->runningUnitTests()) {
            return false;
        }

        return true;
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array<int, string>
     */
    public function provides(): array
    {
        return [
            'workos',
            'workos.auth',
            'workos.session',
            'workos.permissions',
            WorkOSService::class,
            AuthKitService::class,
            SessionService::class,
            PermissionService::class,
        ];
    }
}