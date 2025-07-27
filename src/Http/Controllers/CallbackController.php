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
 * CallbackController handles OAuth callback from WorkOS AuthKit.
 * 
 * This controller processes the authorization code returned from WorkOS
 * and establishes an authenticated session for the user.
 */
class CallbackController extends Controller
{
    public function __construct(
        protected AuthKitService $authKit,
        protected SessionService $sessionService
    ) {}

    /**
     * Handle the OAuth callback from WorkOS AuthKit.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function callback(Request $request): RedirectResponse
    {
        // Check for error parameters from WorkOS
        if ($request->has('error')) {
            return $this->handleAuthError($request);
        }

        // Validate required parameters
        $code = $request->query('code');
        $state = $request->query('state');

        if (!$code) {
            Log::warning('WorkOS callback missing authorization code', [
                'query_params' => $request->query(),
                'session_id' => $request->session()->getId(),
            ]);

            return Redirect::to(Config::get('workos.redirects.login', '/login'))
                ->withErrors(['auth' => 'Authentication failed. Missing authorization code.']);
        }

        // Verify state parameter for CSRF protection
        if (!$this->verifyStateParameter($request, $state)) {
            Log::warning('WorkOS callback state parameter mismatch', [
                'provided_state' => $state,
                'session_id' => $request->session()->getId(),
            ]);

            return Redirect::to(Config::get('workos.redirects.login', '/login'))
                ->withErrors(['auth' => 'Authentication failed. Invalid state parameter.']);
        }

        try {
            // Exchange authorization code for user session
            $userProfile = $this->authKit->processCallback($code, $state);

            if (!$userProfile || empty($userProfile['user'])) {
                throw new \Exception('Failed to retrieve user profile from WorkOS');
            }

            // Create or update user session
            $user = $this->createUserFromProfile($userProfile['user']);

            // Authenticate the user
            Auth::login($user);

            // Store session data
            $this->storeSessionData($request, $userProfile);

            // Clear the auth state from session
            $request->session()->forget('workos_auth_state');

            // Log successful authentication
            Log::info('WorkOS authentication successful', [
                'user_id' => $user->getWorkOSId(),
                'organization_id' => $user->getOrganizationId(),
                'session_id' => $request->session()->getId(),
            ]);

            // Redirect to intended URL or default
            $intendedUrl = $request->session()->pull('workos_intended_url', Config::get('workos.redirects.after_login', '/dashboard'));
            
            return Redirect::to($intendedUrl)->with('success', 'Successfully authenticated!');

        } catch (\Exception $e) {
            Log::error('WorkOS callback error', [
                'error' => $e->getMessage(),
                'code' => $code,
                'state' => $state,
                'session_id' => $request->session()->getId(),
            ]);

            return Redirect::to(Config::get('workos.redirects.login', '/login'))
                ->withErrors(['auth' => 'Authentication failed. Please try again.']);
        }
    }

    /**
     * Handle authentication errors from WorkOS.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    protected function handleAuthError(Request $request): RedirectResponse
    {
        $error = $request->query('error');
        $errorDescription = $request->query('error_description', 'Authentication failed');

        Log::warning('WorkOS authentication error', [
            'error' => $error,
            'error_description' => $errorDescription,
            'session_id' => $request->session()->getId(),
        ]);

        $userMessage = match ($error) {
            'access_denied' => 'Authentication was cancelled or access was denied.',
            'invalid_request' => 'Invalid authentication request. Please try again.',
            'server_error' => 'Authentication service error. Please try again later.',
            default => 'Authentication failed. Please try again.'
        };

        return Redirect::to(Config::get('workos.redirects.login', '/login'))
            ->withErrors(['auth' => $userMessage]);
    }

    /**
     * Verify the state parameter for CSRF protection.
     *
     * @param Request $request
     * @param string|null $providedState
     * @return bool
     */
    protected function verifyStateParameter(Request $request, ?string $providedState): bool
    {
        if (!$providedState) {
            return false;
        }

        $sessionState = $request->session()->get('workos_auth_state');
        
        if (!$sessionState) {
            return false;
        }

        return hash_equals($sessionState, $providedState);
    }

    /**
     * Create a user instance from the WorkOS profile.
     *
     * @param array $userProfile
     * @return mixed
     */
    protected function createUserFromProfile(array $userProfile): \LaravelWorkOS\Auth\Models\WorkOSUser
    {
        // Use the WorkOS user provider to create the user
        $provider = Auth::createUserProvider(['driver' => 'workos']);
        
        if (!$provider instanceof \LaravelWorkOS\Auth\Providers\WorkOSUserProvider) {
            throw new \RuntimeException('Expected WorkOSUserProvider, got ' . get_class($provider));
        }
        
        return $provider->createWorkOSUser($userProfile);
    }

    /**
     * Store session-specific data.
     *
     * @param Request $request
     * @param array $userProfile
     * @return void
     */
    protected function storeSessionData(Request $request, array $authResult): void
    {
        // Store organization context if available
        if (isset($authResult['organization_id'])) {
            $request->session()->put('current_organization_id', $authResult['organization_id']);
        }

        // Store session metadata
        $request->session()->put('workos_auth_time', time());
        
        // Create sealed session with the full auth result
        try {
            $this->sessionService->createSealedSession($authResult);
        } catch (\Exception $e) {
            Log::warning('Failed to create sealed session', [
                'error' => $e->getMessage(),
                'user_id' => $authResult['user']['id'] ?? null,
            ]);
        }
    }
}