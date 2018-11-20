<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;

class Validate
{
    private $jwt;

    public function __construct(Jwt $jwt)
    {
        $this->jwt = $jwt;
    }

    private function tokenStructure(): bool
    {
        return preg_match(
            '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
            $this->jwt->getJwt()
        ) === 1;
    }
}
