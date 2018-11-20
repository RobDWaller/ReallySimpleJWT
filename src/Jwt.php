<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Jwt
{
    public function __construct(string $jwt)
    {
        $this->jwt = $jwt;
    }
}
