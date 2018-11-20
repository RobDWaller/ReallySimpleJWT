<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Jwt
{
    public function __construct(string $jwt)
    {
        $this->jwt = $jwt;
    }

    public function getJwt(): string
    {
        return $this->jwt;
    }
}
