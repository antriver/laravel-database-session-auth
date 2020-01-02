<?php

namespace Antriver\LaravelDatabaseSessionAuth;

use Auth;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;

class DatabaseSessionAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        Auth::extend(
            'database-session',
            function (Container $app, $name, array $config) {
                $guard = new DatabaseSessionGuard(
                    app('auth')->createUserProvider($config['provider']),
                    $app->make(Request::class),
                    !empty($config['checkCookies'])
                );
                $guard->setCookieName(
                    !empty($config['cookieName']) ? $config['cookieName'] : null
                );
                return $guard;
            }
        );
    }
}
