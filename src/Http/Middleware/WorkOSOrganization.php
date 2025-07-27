<?php

declare(strict_types=1);

namespace LaravelWorkOS\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use Symfony\Component\HttpFoundation\Response;

class WorkOSOrganization
{
    /**
     * Handle an incoming request.
     *
     * Ensures the authenticated user belongs to the specified organization.
     */
    public function handle(Request $request, Closure $next, ?string $organizationParam = null): Response
    {
        $user = Auth::user();

        if (!$user instanceof WorkOSUser) {
            return $this->unauthorizedResponse($request, 'User not authenticated with WorkOS');
        }

        $organizationId = $this->getOrganizationId($request, $organizationParam);

        if (!$organizationId) {
            return $this->unauthorizedResponse($request, 'Organization context required');
        }

        if (!$user->belongsToOrganization($organizationId)) {
            return $this->unauthorizedResponse($request, 'User does not belong to the specified organization', [
                'user_id' => $user->getWorkOSId(),
                'organization_id' => $organizationId,
                'user_organizations' => array_column($user->getOrganizations(), 'id'),
            ]);
        }

        // Switch user to the organization context if different from current
        if ($user->getOrganizationId() !== $organizationId) {
            $user->switchOrganization($organizationId);
        }

        // Add organization context to request for downstream use
        $request->attributes->set('workos_organization_id', $organizationId);
        $request->attributes->set('workos_organization', $user->getOrganization($organizationId));

        return $next($request);
    }

    /**
     * Get organization ID from request context.
     */
    protected function getOrganizationId(Request $request, ?string $organizationParam): ?string
    {
        // If specific parameter is provided, use it
        if ($organizationParam) {
            return $request->route($organizationParam) ?? $request->query($organizationParam);
        }

        // Try common organization parameter names
        $paramNames = ['organization', 'org', 'organization_id', 'org_id'];
        
        foreach ($paramNames as $param) {
            $value = $request->route($param) ?? $request->query($param);
            if ($value) {
                return $value;
            }
        }

        // Try organization header
        $headerOrgId = $request->header('X-Organization-ID');
        if ($headerOrgId) {
            return $headerOrgId;
        }

        // Try subdomain-based organization detection if enabled
        if ($this->isSubdomainDetectionEnabled()) {
            $orgId = $this->getOrganizationFromSubdomain($request);
            if ($orgId) {
                return $orgId;
            }
        }

        return null;
    }

    /**
     * Check if subdomain-based organization detection is enabled.
     */
    protected function isSubdomainDetectionEnabled(): bool
    {
        return config('workos.organizations.organization_detection.subdomain', false);
    }

    /**
     * Get organization from subdomain.
     */
    protected function getOrganizationFromSubdomain(Request $request): ?string
    {
        $host = $request->getHost();
        $parts = explode('.', $host);
        
        // If we have at least 3 parts (subdomain.domain.tld), check the subdomain
        if (count($parts) >= 3) {
            $subdomain = $parts[0];
            
            // Skip common subdomains
            $skipSubdomains = ['www', 'api', 'app', 'admin'];
            if (!in_array($subdomain, $skipSubdomains)) {
                // In a real implementation, you'd look up the organization by subdomain
                // For now, we'll assume the subdomain IS the organization slug
                return $subdomain;
            }
        }

        return null;
    }

    /**
     * Return appropriate unauthorized response.
     */
    protected function unauthorizedResponse(Request $request, string $message, array $context = []): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'error' => 'Forbidden',
                'message' => $message,
                'code' => 'WORKOS_ORGANIZATION_ACCESS_DENIED',
                'context' => $context,
            ], 403);
        }

        abort(403, $message);
    }
}