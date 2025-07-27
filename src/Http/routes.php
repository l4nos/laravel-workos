<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use LaravelWorkOS\Http\Controllers\AuthController;
use LaravelWorkOS\Http\Controllers\CallbackController;

/**
 * WorkOS package routes
 * 
 * These routes provide authentication endpoints for WorkOS AuthKit integration.
 * Routes are prefixed with 'workos' and use the 'web' middleware group.
 */

Route::prefix('workos')
    ->middleware(['web'])
    ->name('workos.')
    ->group(function () {
        
        // Authentication routes
        Route::get('login', [AuthController::class, 'login'])->name('login');
        Route::post('logout', [AuthController::class, 'logout'])->name('logout');
        Route::get('callback', [CallbackController::class, 'callback'])->name('callback');
        
        // Organization management routes (requires authentication)
        Route::middleware(['auth'])->group(function () {
            Route::post('organization/switch', [AuthController::class, 'switchOrganization'])
                ->name('organization.switch');
        });
    });