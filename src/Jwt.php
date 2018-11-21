<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Jwt
{
    private $jwt;

    private $secret;

    public function __construct(string $jwt, string $secret)
    {
        $this->jwt = $jwt;

        $this->secret = $secret;
    }

    public function getJwt(): string
    {
        return $this->jwt;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }
}
