<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Exception\ParseException;
use ReallySimpleJWT\Interfaces\Decode;

/**
 * This class parses a JSON Web Token.
 *
 * The token is housed in the Jwt value object. The class outputs a Parsed value
 * object to provide access to the data held within the JWT header and payload.
 */
class Parse
{
    /**
     * The JSON Web Token value object.
     */
    private Jwt $jwt;

    /**
     * A class to decode JWT tokens.
     */
    private Decode $decode;

    /**
     * Parse constructor
     */
    public function __construct(Jwt $jwt, Decode $decode)
    {
        $this->jwt = $jwt;

        $this->decode = $decode;
    }

    /**
     * Parse the JWT and generate the Parsed Value Object.
     */
    public function parse(): Parsed
    {
        return new Parsed(
            $this->jwt,
            $this->getDecodedHeader(),
            $this->getDecodedPayload(),
            $this->getSignature()
        );
    }

    /**
     * Split the JWT into it's component parts, the header, payload and
     * signature are all separated by a dot.
     *
     * @return string[]
     */
    private function splitToken(): array
    {
        return explode('.', $this->jwt->getToken());
    }

    /**
     * Get the header string from the JWT string. This is the first part of the
     * JWT string.
     */
    private function getHeader(): string
    {
        return $this->splitToken()[0] ?? '';
    }

    /**
     * Get the payload string from the JWT string. This is the second part of
     * the JWT string.
     */
    private function getPayload(): string
    {
        return $this->splitToken()[1] ?? '';
    }

    /**
     * Get the signature string from the JWT string. This is the third part of
     * the JWT string.
     */
    public function getSignature(): string
    {
        return $this->splitToken()[2] ?? '';
    }

    /**
     * Retrieve the expiration claim from the JWT.
     *
     * @throws ParseException
     */
    public function getExpiration(): int
    {
        $payload = $this->getDecodedPayload();

        if (isset($payload['exp'])) {
            return $payload['exp'];
        }

        throw new ParseException('Expiration claim is not set.', 6);
    }

    /**
     * Retrieve the not before claim from the JWT.
     *
     * @throws ParseException
     */
    public function getNotBefore(): int
    {
        $payload = $this->getDecodedPayload();

        if (isset($payload['nbf'])) {
            return $payload['nbf'];
        }

        throw new ParseException('Not Before claim is not set.', 7);
    }

    /**
     * Retrieve the audience claim from the JWT.
     *
     * @return string|string[]
     * @throws ParseException
     */
    public function getAudience()
    {
        $payload = $this->getDecodedPayload();

        if (isset($payload['aud'])) {
            return $payload['aud'];
        }

        throw new ParseException('Audience claim is not set.', 11);
    }

    /**
     * Retrieve the algorithm claim from the JWT.
     *
     * @throws ParseException
     */
    public function getAlgorithm(): string
    {
        $header = $this->getDecodedHeader();

        if (isset($header['alg'])) {
            return $header['alg'];
        }

        throw new ParseException('Algorithm claim is not set.', 13);
    }

    /**
     * Decode the JWT header string to an associative array.
     *
     * @return mixed[]
     */
    public function getDecodedHeader(): array
    {
        return $this->decode->decode(
            $this->getHeader()
        );
    }

    /**
     * Decode the JWT payload string to an associative array.
     *
     * @return mixed[]
     */
    public function getDecodedPayload(): array
    {
        return $this->decode->decode(
            $this->getPayload()
        );
    }

    /**
     * Retrieve the JSON Web Token string.
     */
    public function getToken(): string
    {
        return $this->jwt->getToken();
    }

    /**
     * Retrieve the JSON Web Token secret.
     */
    public function getSecret(): string
    {
        return $this->jwt->getSecret();
    }
}
