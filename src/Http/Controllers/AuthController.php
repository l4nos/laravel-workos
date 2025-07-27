<?php

declare(strict_types=1);

namespace LaravelWorkOS\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Config;
use LaravelWorkOS\Services\AuthKitService;
use LaravelWorkOS\Services\SessionService;

/**
 * AuthController handles WorkOS AuthKit authentication endpoints.
 * 
 * This controller provides endpoints for:
 * - Redirecting users to WorkOS AuthKit login
 * - Processing logout requests
 * - Organization switching
 */
class AuthController extends Controller
{
    public function __construct(
        protected AuthKitService $authKit,
        protected SessionService $sessionService
    ) {}

    /**
     * Redirect user to WorkOS AuthKit for authentication.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function login(Request $request): RedirectResponse
    {
        // Validate organization parameter if provided
        $organization = $request->query('organization');
        if ($organization && !$this->isValidOrganization($organization)) {
            return Redirect::back()->withErrors([
                'organization' => 'Invalid organization specified.'
            ]);
        }

        try {
            // Generate authorization URL with state parameter for CSRF protection
            $authUrl = $this->authKit->generateAuthorizationUrl([
                'organization' => $organization,
                'state' => $this->generateStateParameter($request),
                'redirect_uri' => $this->getCallbackUrl($request),
            ]);

            // Store state parameter in session for verification
            $request->session()->put('workos_auth_state', $authUrl['state']);
            
            // Store intended URL for post-authentication redirect
            if ($request->has('redirect')) {
                $request->session()->put('workos_intended_url', $request->query('redirect'));
            }

            return Redirect::to($authUrl['url']);

        } catch (\Exception $e) {
            Log::error('WorkOS AuthKit login error', [
                'error' => $e->getMessage(),
                'organization' => $organization,
            ]);

            return Redirect::back()->withErrors([
                'auth' => 'Authentication service temporarily unavailable. Please try again.'
            ]);
        }
    }

    /**
     * Handle logout request and redirect to WorkOS logout.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function logout(Request $request): RedirectResponse
    {
        try {
            $user = Auth::user();

            // Clear Laravel session first
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            // Clear WorkOS session if user was authenticated with WorkOS
            if ($user instanceof \LaravelWorkOS\Auth\Models\WorkOSUser) {
                try {
                    $this->sessionService->clearSession();
                } catch (\Exception $e) {
                    Log::warning('Failed to clear WorkOS session', [
                        'error' => $e->getMessage(),
                        'user_id' => $user->getWorkOSId(),
                    ]);
                }
            }

            return Redirect::to(Config::get('workos.redirects.logout', '/'));

        } catch (\Exception $e) {
            Log::error('WorkOS logout error', [
                'error' => $e->getMessage(),
                'user_id' => Auth::id(),
            ]);

            // Force local logout even if WorkOS logout fails
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return Redirect::to(Config::get('workos.redirects.logout', '/'))
                ->with('warning', 'Logout completed, but there may have been an issue with the authentication service.');
        }
    }

    /**
     * Handle organization switching for multi-tenant applications.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function switchOrganization(Request $request): RedirectResponse
    {
        $request->validate([
            'organization_id' => 'required|string',
        ]);

        $user = Auth::user();
        if (!$user instanceof \LaravelWorkOS\Auth\Models\WorkOSUser) {
            return Redirect::route('login');
        }

        $organizationId = $request->input('organization_id');

        try {
            // Verify user has access to the organization
            if (!$user->belongsToOrganization($organizationId)) {
                return Redirect::back()->withErrors([
                    'organization' => 'You do not have access to this organization.'
                ]);
            }

            // Update session with new organization context
            $request->session()->put('current_organization_id', $organizationId);

            // Switch user's organization context
            $user->switchOrganization($organizationId);

            // Redirect to intended URL or dashboard
            $redirectUrl = $request->input('redirect', '/dashboard');
            
            return Redirect::to($redirectUrl)->with('success', 'Organization switched successfully.');

        } catch (\Exception $e) {
            Log::error('Organization switch error', [
                'error' => $e->getMessage(),
                'user_id' => $user->getWorkOSId(),
                'organization_id' => $organizationId,
            ]);

            return Redirect::back()->withErrors([
                'organization' => 'Failed to switch organization. Please try again.'
            ]);
        }
    }

    /**
     * Generate a secure state parameter for CSRF protection.
     *
     * @param Request $request
     * @return string
     */
    protected function generateStateParameter(Request $request): string
    {
        return hash('sha256', $request->session()->getId() . time() . Config::get('app.key'));
    }

    /**
     * Get the callback URL for the current request.
     *
     * @param Request $request
     * @return string
     */
    protected function getCallbackUrl(Request $request): string
    {
        $configuredUrl = Config::get('workos.redirects.callback');
        
        if ($configuredUrl && filter_var($configuredUrl, FILTER_VALIDATE_URL)) {
            return $configuredUrl;
        }

        return $request->url() . '/callback';
    }

    /**
     * Validate organization identifier.
     *
     * @param string $organization
     * @return bool
     */
    protected function isValidOrganization(string $organization): bool
    {
        // Basic validation - organization should be a valid WorkOS organization ID or domain
        if (str_starts_with($organization, 'org_')) {
            return strlen($organization) > 4 && strlen($organization) <= 50;
        }

        // Domain validation for organization domains
        return filter_var($organization, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
    }
}