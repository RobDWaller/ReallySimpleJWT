<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

/**
 * Value object for the generated JSON Web Token, takes the token and
 * the secret.
 */
class Jwt
{
    /**
     * The JSON Web Token string
     */
    private string $token;

    /**
    * The secret used to create the JWT signature
    */
    private string $secret;

    public function __construct(string $token, string $secret)
    {
        $this->token = $token;

        $this->secret = $secret;
    }

    /**
     * Return the JSON Web Token String
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Return the secret used to encode the JWT signature
     */
    public function getSecret(): string
    {
        return $this->secret;
    }
}
