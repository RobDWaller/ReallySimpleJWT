<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Decode;

/**
 * This class parses a JSON Web Token. The token is housed in the Jwt value
 * object. The class outputs a Parsed value object to provide access to the data
 * held within the JWT header and payload.
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
}
