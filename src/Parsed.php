<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;

/**
 * This value object is generated when the JWT has been parsed.
 *
 * It contains the original JWT value object, and the header and payload
 * associative arrays. The class also offers helper methods which provide
 * access to the header and payload claim data.
 */
class Parsed
{
    /**
     * The pre-parsed JWT value object
     */
    private Jwt $jwt;

    /**
     * Associative array of header claims
     *
     * @var mixed[]
     */
    private array $header;

    /**
     * Associative array of payload claims
     *
     * @var mixed[]
     */
    private array $payload;

    /**
     * The JWT signature string
     */
    private string $signature;

    /**
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function __construct(Jwt $jwt, array $header, array $payload, string $signature)
    {
        $this->jwt = $jwt;

        $this->header = $header;

        $this->payload = $payload;

        $this->signature = $signature;
    }

    /**
     * Return the original JWT value object.
     */
    public function getJwt(): Jwt
    {
        return $this->jwt;
    }

    /**
     * Get the header claims data as an associative array.
     *
     * @return mixed[]
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Access the algorithm claim from the header.
     */
    public function getAlgorithm(): string
    {
        return $this->header['alg'] ?? '';
    }

    /**
     * Access the type claim from the header.
     */
    public function getType(): string
    {
        return $this->header['typ'] ?? '';
    }

    /**
     * Access the content type claim from the header.
     */
    public function getContentType(): string
    {
        return $this->header['cty'] ?? '';
    }

    /**
     * Get the payload claims data as an associative array.
     *
     * @return mixed[]
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Access the issuer claim from the payload.
     */
    public function getIssuer(): string
    {
        return $this->payload['iss'] ?? '';
    }

    /**
     * Access the subject claim from the payload.
     */
    public function getSubject(): string
    {
        return $this->payload['sub'] ?? '';
    }

    /**
     * Access the audience claim from the payload.
     *
     * @return string|string[]
     */
    public function getAudience()
    {
        return $this->payload['aud'] ?? '';
    }

    /**
     * Access the expiration claim from the payload.
     */
    public function getExpiration(): int
    {
        return $this->payload['exp'] ?? 0;
    }

    /**
     * Calculate how long the token has until it expires.
     */
    public function getExpiresIn(): int
    {
        $expiresIn = $this->getExpiration() - time();
        return $expiresIn > 0 ? $expiresIn : 0;
    }

    /**
     * Access the not before claim from the payload.
     */
    public function getNotBefore(): int
    {
        return $this->payload['nbf'] ?? 0;
    }

    /**
     * Calculate how long until the Not Before claim expires and the token
     * is usable.
     */
    public function getUsableIn(): int
    {
        $usableIn = $this->getNotBefore() - time();
        return $usableIn > 0 ? $usableIn : 0;
    }

    /**
     * Access the issued at claim from the payload.
     */
    public function getIssuedAt(): int
    {
        return $this->payload['iat'] ?? 0;
    }

    /**
     * Access the JWT Id claim from the payload.
     */
    public function getJwtId(): string
    {
        return $this->payload['jti'] ?? '';
    }

    /**
     * Get the JWT signature string if required.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }
}
