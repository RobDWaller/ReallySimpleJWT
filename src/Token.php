<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

/**
 * A simple Package for creating JSON Web Tokens that uses HMAC SHA256 to sign
 * signatures.
 *
 * Exposes a simple interface to allow you to create a token that stores a user
 * identifier. The Package is set up to allow extension and the use of larger
 * payloads. You can use your own encoding if you choose.
 *
 * For more information on JSON Web Tokens please see https://jwt.io
 * along with the RFC https://tools.ietf.org/html/rfc7519
 *
 * @author Rob Waller <rdwaller1984@gmail.com>
 */
class Token
{
    /**
     * Create a JSON Web Token that contains a user identifier and a basic
     * payload including issued at, expiration and issuer.
     *
     * @see Tokens::create()
     */
    public static function create(string|int $userId, string $secret, int $expiration, string $issuer): string
    {
        $tokens = new Tokens();
        return $tokens->create(
            'user_id',
            $userId,
            $secret,
            $expiration,
            $issuer
        )->getToken();
    }

    /**
     * @see Tokens::customPayload()
     * @param mixed[] $payload
     */
    public static function customPayload(array $payload, string $secret): string
    {
        $tokens = new Tokens();
        return $tokens->customPayload($payload, $secret)->getToken();
    }

    /**
     * @see Tokens::validate()
     */
    public static function validate(string $token, string $secret): bool
    {
        $tokens = new Tokens();
        return $tokens->validate($token, $secret);
    }

    /**
     * @see Tokens::getHeader()
     * @return mixed[]
     */
    public static function getHeader(string $token): array
    {
        $tokens = new Tokens();
        return $tokens->getHeader($token);
    }

    /**
     * @see Tokens::getPayload()
     * @return mixed[]
     */
    public static function getPayload(string $token): array
    {
        $tokens = new Tokens();
        return $tokens->getPayload($token);
    }

    /**
     * @see Tokens::builder()
     */
    public static function builder(string $secret): Build
    {
        $tokens = new Tokens();
        return $tokens->builder($secret);
    }

    /**
     * @see Tokens::parser()
     */
    public static function parser(string $token): Parse
    {
        $tokens = new Tokens();
        return $tokens->parser($token);
    }

    /**
     * @see Tokens::validator()
     */
    public static function validator(string $token, string $secret): Validate
    {
        $tokens = new Tokens();
        return $tokens->validator($token, $secret);
    }

    /**
     * @see Tokens::validateExpiration()
     */
    public static function validateExpiration(string $token): bool
    {
        $tokens = new Tokens();
        return $tokens->validateExpiration($token);
    }

    /**
     * @see Tokens::validateNotBefore()
     */
    public static function validateNotBefore(string $token): bool
    {
        $tokens = new Tokens();
        return $tokens->validateNotBefore($token);
    }
}
