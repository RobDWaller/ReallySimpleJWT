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

    private $signature;

    public function __construct(Jwt $jwt, stdClass $header, stdClass $payload, string $signature)
    {
        $this->jwt = $jwt;

        $this->header = $header;

        $this->payload = $payload;

        $this->signature = $signature;
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

    public function getSignature(): string
    {
        return $this->signature;
    }
}
