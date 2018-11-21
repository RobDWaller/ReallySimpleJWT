<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use Carbon\Carbon;

class Validate
{
    public function tokenStructure(string $jwt): bool
    {
        return preg_match(
            '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
            $jwt
        ) === 1;
    }

    public function expiration(int $expiration): bool
    {
        return $expiration >= time();
    }
}
