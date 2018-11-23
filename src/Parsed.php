<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use stdClass;

class Parsed
{
    private $jwt;

    private $header;

    private $payload;

    public function __construct(Jwt $jwt, stdClass $header, stdClass $payload)
    {
        $this->jwt = $jwt;

        $this->header = $header;

        $this->payload = $payload;
    }

    public function getJwt(): Jwt
    {
        return $this->jwt;
    }

    public function getHeader(): stdClass
    {
        return $this->header;
    }

    public function getPayload(): stdClass
    {
        return $this->payload;
    }
}
