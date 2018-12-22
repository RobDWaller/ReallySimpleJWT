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

    public function notBefore(int $notBefore): bool
    {
        return $notBefore <= time();
    }

    public function signature(string $signature, string $comparison): bool
    {
        return hash_equals($signature, $comparison);
    }

    public function secret(string $secret): bool
    {
        if (!preg_match(
            '/^.*(?=.{12,}+)(?=.*[0-9]+)(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[\*&!@%\^#\$]+).*$/',
            $secret
        )) {
            return false;
        }

        return true;
    }
}
