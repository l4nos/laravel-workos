<?php

declare(strict_types=1);

namespace LaravelWorkOS\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LaravelWorkOS\Auth\Models\WorkOSUser;
use LaravelWorkOS\Services\PermissionService;
use Symfony\Component\HttpFoundation\Response;

class WorkOSPermissions
{
    protected PermissionService $permissionService;

    public function __construct(PermissionService $permissionService)
    {
        $this->permissionService = $permissionService;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, string $permissions, string $operator = 'and'): Response
    {
        $user = Auth::user();

        if (!$user instanceof WorkOSUser) {
            return $this->unauthorizedResponse($request, 'User not authenticated with WorkOS');
        }

        $requiredPermissions = $this->parsePermissions($permissions);
        $organizationId = $this->getOrganizationId($request, $user);

        $hasPermission = $this->checkPermissions(
            $user,
            $requiredPermissions,
            $operator,
            $organizationId
        );

        if (!$hasPermission) {
            return $this->unauthorizedResponse($request, 'Insufficient permissions', [
                'required_permissions' => $requiredPermissions,
                'user_permissions' => $user->getPermissions($organizationId),
                'organization_id' => $organizationId,
            ]);
        }

        return $next($request);
    }

    /**
     * Parse permissions string into array.
     */
    protected function parsePermissions(string $permissions): array
    {
        return array_filter(array_map('trim', explode(',', $permissions)));
    }

    /**
     * Get organization ID from request context.
     */
    protected function getOrganizationId(Request $request, WorkOSUser $user): ?string
    {
        // Try to get from route parameter
        $routeOrgId = $request->route('organization');
        if ($routeOrgId && $user->belongsToOrganization($routeOrgId)) {
            return $routeOrgId;
        }

        // Try to get from query parameter
        $queryOrgId = $request->query('organization_id');
        if ($queryOrgId && $user->belongsToOrganization($queryOrgId)) {
            return $queryOrgId;
        }

        // Try to get from header
        $headerOrgId = $request->header('X-Organization-ID');
        if ($headerOrgId && $user->belongsToOrganization($headerOrgId)) {
            return $headerOrgId;
        }

        // Fall back to user's current organization
        return $user->getOrganizationId();
    }

    /**
     * Check if user has required permissions.
     */
    protected function checkPermissions(
        WorkOSUser $user,
        array $requiredPermissions,
        string $operator,
        ?string $organizationId
    ): bool {
        if (empty($requiredPermissions)) {
            return true;
        }

        switch (strtolower($operator)) {
            case 'and':
                return $user->hasAllPermissions($requiredPermissions, $organizationId);
            case 'or':
                return $user->hasAnyPermission($requiredPermissions, $organizationId);
            default:
                return $user->hasAllPermissions($requiredPermissions, $organizationId);
        }
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
                'code' => 'WORKOS_INSUFFICIENT_PERMISSIONS',
                'context' => $context,
            ], 403);
        }

        abort(403, $message);
    }
}