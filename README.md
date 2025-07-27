# Laravel WorkOS Package

A comprehensive Laravel package that provides deep integration with [WorkOS](https://workos.com) authentication and authorization services. Unlike the official WorkOS Laravel package, this implementation provides full Laravel ecosystem integration including custom auth guards, user providers, middleware, and facades.

## ✨ Features

### 🔐 **Three Authentication Strategies**
- **Session-Based (AuthKit)**: Hosted authentication flow with sealed session management
- **JWT API Authentication**: Secure token-based API authentication with proper signature verification
- **Server-to-Server**: Direct API integration for administrative operations

### 🚀 **Laravel-Native Integration**
- **Custom Authentication Guards**: `workos-session`, `workos-api`, `workos-server`
- **Uses Laravel's Built-in Auth**: No custom authentication middleware - extends Laravel's auth system
- **Stateless Design**: Zero database requirements in consuming applications
- **RBAC Integration**: WorkOS permission system with middleware protection

### ⚡ **Performance & Security**
- **Proper JWT Verification**: Cryptographic signature validation using WorkOS public keys
- **Intelligent Caching**: User data, permissions, and API responses
- **Rate Limiting**: API call optimization and compliance
- **Multi-Organization Support**: Organization context switching and scoped permissions

### 🛠️ **Developer Experience**
- **Facade System**: Convenient static access to all WorkOS services
- **Console Commands**: Installation, testing, and maintenance utilities
- **Comprehensive Testing**: 90%+ test coverage with unit, integration, and feature tests
- **Laravel 9, 10, 11 Compatible**: Multi-version support

## 📦 Installation

### 1. Install the Package

```bash
composer require l4nos/laravel-workos
```

### 2. Run the Installation Command

```bash
php artisan workos:install
```

This will:
- Publish the configuration file
- Set up environment variables
- Register authentication drivers
- Verify the installation

### 3. Configure Environment Variables

Add your WorkOS credentials to `.env`:

```env
# Required WorkOS Configuration
WORKOS_API_KEY=sk_your_api_key_here
WORKOS_CLIENT_ID=client_your_client_id_here
WORKOS_COOKIE_PASSWORD=your-32-character-strong-password

# Redirect Configuration
WORKOS_REDIRECT_URI=https://yourapp.com/auth/callback
WORKOS_LOGIN_URI=https://yourapp.com/login
WORKOS_LOGOUT_REDIRECT=https://yourapp.com/
```

### 4. Configure Authentication Guards

Add WorkOS guards to your `config/auth.php`:

```php
'guards' => [
       
    // Either use WorkOS drivers in your own guards
    'web' => [
        'driver' => 'workos-session',
        'provider' => 'workos',
    ],

    'api' => [
        'driver' => 'workos-api',
        'provider' => 'workos'
    ],

    // Or add WorkOS Guards
    'workos-session' => [
        'driver' => 'workos-session',
        'provider' => 'workos',
    ],
    
    'workos-api' => [
        'driver' => 'workos-api',
        'provider' => 'workos',
    ],
    
    'workos-server' => [
        'driver' => 'workos-server',
        'provider' => 'workos',
    ],
],

'providers' => [
    // Set workOS driver for user provider
    // This will make auth()->user() return the WorkOS user
    'users' => [
        'driver' => 'workos'
    ]
],
```

### 5. Test Your Configuration

```bash
php artisan workos:test
```

## 🚀 Quick Start

### Session-Based Web Authentication

```php
// routes/web.php
Route::middleware(['auth:api'])->group(function () {
    Route::get('/dashboard', function () {
        $user = auth()->user(); // WorkOSUser instance
        
        return view('dashboard', [
            'user' => $user,
            'permissions' => $user->getPermissions(),
            'organization' => $user->getOrganizationId(),
        ]);
    });
});

// With permission protection
Route::middleware(['auth:web', 'workos.permissions:admin'])
    ->get('/admin', AdminController::class);
```

### JWT API Authentication using custom guard

```php
// routes/api.php
Route::middleware(['auth:workos-api'])->group(function () {
    Route::get('/user', function () {
        return auth()->user()->toArray();
    });
    
    Route::get('/profile', ApiController::class);
});

// Organization-scoped API routes
Route::middleware(['auth:workos-api', 'workos.organization'])
    ->prefix('api/org/{organization}')
    ->group(function () {
        Route::get('/dashboard', 'Api\OrganizationController@dashboard');
    });
```

### Using Facades

```php
use LaravelWorkOS\Facades\WorkOS;
use LaravelWorkOS\Facades\WorkOSAuth;
use LaravelWorkOS\Facades\WorkOSPermissions;

// Core WorkOS operations
$users = WorkOS::getUserManagement()->listUsers();
$organizations = WorkOS::getOrganizations()->listOrganizations();

// Authentication operations
$authUrl = WorkOSAuth::generateAuthorizationUrl([
    'organization' => 'org_123',
    'redirect_uri' => route('auth.callback'),
]);

// Permission operations
$hasPermission = WorkOSPermissions::userHasPermission(
    $userId, 
    'manage-users',
    $organizationId
);
```

## 📚 Documentation

### Core Concepts

#### Authentication Guards
The package provides three custom authentication guards that integrate with Laravel's auth system:

- **`workos-session`**: For web applications using WorkOS AuthKit
- **`workos-api`**: For API endpoints with JWT token authentication  
- **`workos-server`**: For server-to-server administrative operations

#### User Provider
The `workos` user provider fetches user data directly from WorkOS APIs without requiring local database storage.

#### Middleware
- **`workos.permissions`**: RBAC permission checking
- **`workos.organization`**: Organization context validation
- **`workos.protected`**: Convenience group (auth + permissions)

### Configuration

The package automatically publishes a comprehensive configuration file at `config/workos.php`. Key sections include:

```php
return [
    // Core API credentials
    'api_key' => env('WORKOS_API_KEY'),
    'client_id' => env('WORKOS_CLIENT_ID'),
    'cookie_password' => env('WORKOS_COOKIE_PASSWORD'),
    
    // Redirect URIs
    'redirects' => [
        'login' => env('WORKOS_LOGIN_URI', '/login'),
        'callback' => env('WORKOS_REDIRECT_URI', '/auth/callback'),
        'logout' => env('WORKOS_LOGOUT_REDIRECT', '/'),
        'after_login' => env('WORKOS_AFTER_LOGIN_REDIRECT', '/dashboard'),
    ],
    
    // Caching configuration
    'cache' => [
        'enabled' => true,
        'ttl' => ['user' => 3600, 'permissions' => 1800],
    ],
    
    // JWT security settings
    'jwt' => [
        'verify_signature' => true,
        'clock_skew' => 60,
        'algorithm' => 'RS256',
    ],
];
```

Authentication guards are configured in Laravel's standard `config/auth.php` file, not in the WorkOS configuration.

### Advanced Usage

#### Multi-Organization Applications

```php
// Organization switching
Route::post('/switch-organization', function (Request $request) {
    $request->validate(['organization_id' => 'required|string']);
    
    if (auth()->user()->hasOrganizationAccess($request->organization_id)) {
        session(['current_organization_id' => $request->organization_id]);
        return redirect('/dashboard');
    }
    
    return back()->withErrors(['organization' => 'Access denied']);
});

// Organization-scoped routes
Route::middleware(['auth:workos-session', 'workos.organization'])
    ->prefix('org/{organization}')
    ->group(function () {
        Route::get('/users', 'OrganizationUserController@index');
        Route::get('/settings', 'OrganizationSettingsController@show');
    });
```

#### Permission-Based Access Control

```php
// Middleware usage
Route::middleware(['auth:workos-session', 'workos.permissions:admin,manage-users'])
    ->resource('users', UserController::class);

// In controllers
class UserController extends Controller 
{
    public function index()
    {
        if (!auth()->user()->hasPermission('view-users')) {
            abort(403);
        }
        
        return view('users.index');
    }
}

// In Blade templates
@can('edit-users')
    <a href="{{ route('users.edit', $user) }}">Edit User</a>
@endcan
```

#### Console Commands

```bash
# Installation and setup
php artisan workos:install --verify

# Test WorkOS connectivity
php artisan workos:test --detailed --user-id=user_123

# Session management
php artisan workos:clear-sessions --expired
php artisan workos:clear-sessions --user-id=user_123
php artisan workos:clear-sessions --organization-id=org_456
```

## 🔧 Architecture

### Package Structure
```
src/
├── Auth/
│   ├── Guards/              # Custom authentication guards
│   ├── Models/              # WorkOS user model
│   └── Providers/           # User provider implementation
├── Http/
│   ├── Controllers/         # AuthKit controllers
│   └── Middleware/          # RBAC and organization middleware
├── Services/                # Core WorkOS service wrappers
├── Facades/                 # Convenient static access
├── Console/Commands/        # Management commands
└── WorkOSServiceProvider.php
```

### Security Model

#### JWT Verification
Unlike basic implementations, this package properly verifies JWT signatures:

```php
// ❌ INSECURE (what others do)
$payload = json_decode(base64_decode(explode('.', $token)[1]), true);

// ✅ SECURE (what this package does)
$jwks = $this->fetchWorkOSPublicKeys();
$payload = JWT::decode($token, $jwks, ['RS256']);
```

#### Session Security
- Encrypted sealed sessions using WorkOS session management
- CSRF protection with state parameters
- Secure cookie handling with proper flags
- Session fixation protection

## 🧪 Testing

The package includes comprehensive testing utilities:

```bash
# Run all tests
composer test

# Run with coverage
composer test-coverage

# Run specific test suites
vendor/bin/phpunit --testsuite=Unit
vendor/bin/phpunit --testsuite=Feature
vendor/bin/phpunit --testsuite=Integration
```

### Test Utilities

```php
use LaravelWorkOS\Tests\TestCase;

class MyWorkOSTest extends TestCase
{
    /** @test */
    public function it_authenticates_users()
    {
        $user = $this->createMockWorkOSUser([
            'permissions' => ['admin', 'manage-users']
        ]);
        
        auth('workos-session')->login($user);
        
        $this->assertAuthenticated('workos-session');
        $this->assertTrue(auth()->user()->hasPermission('admin'));
    }
}
```

## 🔄 Migration from Official Package

This package is designed as a drop-in replacement for the inadequate official WorkOS Laravel package:

### What's Better
- ✅ **Proper JWT verification** (vs insecure base64 decode)
- ✅ **Laravel-native auth integration** (vs custom middleware)
- ✅ **Comprehensive caching** (vs API calls on every request)
- ✅ **Multi-organization support** (vs single-tenant only)
- ✅ **Production-ready security** (vs development-only features)
- ✅ **Extensive testing** (vs minimal test coverage)

### Migration Steps
1. Remove the official package: `composer remove workos/laravel`
2. Install this package: `composer require l4nos/laravel-workos`
3. Run migration: `php artisan workos:install`
4. Update route middleware from custom to Laravel's `auth:workos-session`
5. Test your application: `php artisan workos:test`


### Development Setup

```bash
git clone https://github.com/l4nos/laravel-workos.git
cd laravel-workos
composer install
cp .env.example .env
vendor/bin/phpunit
```

## 📄 License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

## 🙏 Credits

- Built by [l4nos](https://github.com/l4nos) (Rob)
- Inspired by the need for a proper WorkOS Laravel integration
- Powered by [WorkOS](https://workos.com) APIs

---

**Laravel WorkOS Package** - *The WorkOS integration Laravel deserves* 🚀