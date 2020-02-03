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
     *
     * @var string $token
     */
    private $token;

    /**
    * The secret used to create the JWT signature
    *
    * @var string $secret
    */
    private $secret;

    /**
     * JWT Constructor
     *
     * @param string $token
     * @param string $secret
     */
    public function __construct(string $token, string $secret)
    {
        $this->token = $token;

        $this->secret = $secret;
    }

    /**
     * Return the JSON Web Token String
     *
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Return the secret used to encode the JWT signature
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }
}
