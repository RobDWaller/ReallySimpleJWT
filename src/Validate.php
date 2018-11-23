<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use Carbon\Carbon;
use ReallySimpleJWT\Helper\Signature;

class Validate
{
    public function structure(string $jwt): bool
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

    public function signature(Signature $signature, string $comparison): bool
    {
        return hash_equals($signature->get(), $comparison);
    }
}
