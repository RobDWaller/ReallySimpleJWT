<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;

class Parsed
{
    private $jwt;

    private $header;

    public function __construct(Jwt $jwt, $header)
    {
        $this->jwt = $jwt;

        $this->header = $header;
    }

    public function getJwt(): Jwt
    {
        return $this->jwt;
    }

    public function getHeader()
    {
        return $this->header;
    }
}
