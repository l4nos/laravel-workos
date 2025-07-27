# Changelog

All notable changes to `laravel-workos` will be documented in this file.

## [Unreleased]

## [1.0.0] - 2024-01-XX

### Added
- Initial release of Laravel WorkOS Package
- **Authentication Guards**: Three custom guard drivers (`workos-session`, `workos-api`, `workos-server`)
- **Security**: Proper JWT signature verification using WorkOS public keys
- **AuthKit Integration**: Complete session-based authentication flow
- **User Provider**: Stateless user provider with WorkOS API integration
- **User Model**: Enhanced WorkOS user model with multi-organization support
- **Middleware Suite**: RBAC permissions and organization context middleware
- **Service Layer**: Core WorkOS API wrappers with caching and retry logic
- **Facades**: Convenient static access to all WorkOS services
- **Console Commands**: Installation, testing, and session management utilities
- **Comprehensive Testing**: Unit, integration, and feature test suites
- **Documentation**: Complete usage guides and examples

### Security
- **JWT Verification**: Cryptographic signature validation (not just base64 decode)
- **Session Security**: Encrypted sealed sessions with CSRF protection
- **Rate Limiting**: API call optimization and abuse prevention
- **Cache Security**: Secure caching with proper TTL management

### Features
- **Laravel 9, 10, 11 Support**: Multi-version compatibility
- **Zero Database Requirements**: Fully stateless design
- **Multi-Organization Support**: Organization switching and scoped permissions
- **RBAC Integration**: WorkOS permission system with middleware protection
- **Performance Optimization**: Intelligent caching and API efficiency
- **Developer Tools**: Rich debugging and diagnostic utilities

### Architecture
- **Laravel-Native**: Extends Laravel's auth system (no custom auth middleware)
- **PSR Standards**: Full PSR-1, PSR-2, PSR-4, PSR-12 compliance
- **SOLID Principles**: Clean, maintainable, and extensible code architecture
- **Dependency Injection**: Proper service container integration
- **Event Integration**: Laravel authentication events support

### Breaking Changes
- This is the initial release, so no breaking changes from previous versions
- Replaces the inadequate official WorkOS Laravel package with superior architecture

### Migration Notes
- **From Official Package**: See README.md for complete migration guide
- **Configuration**: Uses environment-based configuration with sensible defaults
- **Route Protection**: Use Laravel's `auth:workos-session` instead of custom middleware

---

## Release Notes Template

### [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Bug fixes

### Security
- Security improvements and fixes

---

## Upgrade Guide

### Upgrading to 1.0.0 from Official Package

1. **Remove Official Package**:
   ```bash
   composer remove workos/laravel
   ```

2. **Install This Package**:
   ```bash
   composer require your-org/laravel-workos
   php artisan workos:install
   ```

3. **Update Route Middleware**:
   ```php
   // Before (official package)
   Route::middleware(['workos'])->group(function () {
       // routes
   });
   
   // After (this package)
   Route::middleware(['auth:workos-session'])->group(function () {
       // routes
   });
   ```

4. **Update Configuration**:
   - Environment variables remain the same
   - New caching and security options available
   - Test configuration: `php artisan workos:test`

5. **Test Your Application**:
   ```bash
   php artisan workos:test --detailed
   ```

---

## Maintenance Policy

### Supported Versions

| Version | Laravel | PHP     | Support Status |
|---------|---------|---------|----------------|
| 1.x     | 9,10,11 | 8.1-8.3 | Active         |

### Security Updates
Security vulnerabilities will be addressed in all currently supported versions.

### Release Schedule
- **Major releases**: Annually (breaking changes)
- **Minor releases**: Quarterly (new features)
- **Patch releases**: As needed (bug fixes, security)

---