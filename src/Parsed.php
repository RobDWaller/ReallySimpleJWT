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

    public function __construct(Jwt $jwt, array $header, array $payload, string $signature)
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

    public function getHeader(): array
    {
        return $this->header;
    }

    public function getType(): string
    {
        return $this->header['typ'] ?? '';
    }

    public function getContentType(): string
    {
        return $this->header['cty'] ?? '';
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function getIssuer(): string
    {
        return $this->payload['iss'] ?? '';
    }

    public function getSubject(): string
    {
        return $this->payload['sub'] ?? '';
    }

    public function getAudience(): string
    {
        return $this->payload['aud'] ?? '';
    }

    public function getExpiration(): int
    {
        return $this->payload['exp'] ?? 0;
    }

    public function getNotBefore(): int
    {
        return $this->payload['nbf'] ?? 0;
    }

    public function getIssuedAt(): int
    {
        return $this->payload['iat'] ?? 0;
    }

    public function getJwtId(): string
    {
        return $this->payload['jti'] ?? '';
    }

    public function getSignature(): string
    {
        return $this->signature;
    }
}
