<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Tokens;

/**
 * A simple Package for creating JSON Web Tokens that uses HMAC SHA256 to sign
 * signatures. Exposes a simple interface to allow you to create a token
 * that stores a user identifier. The Package is set up to allow extension and
 * the use of larger payloads. You can use your own encoding if you choose.
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
     * @param mixed $userId
     */
    public static function create($userId, string $secret, int $expiration, string $issuer): string
    {
        $tokens = new Tokens();
        return $tokens->createBasicToken(
            'user_id',
            $userId,
            $secret,
            $expiration,
            $issuer
        )->getToken();
    }

    /**
     * Create a JSON Web Token with a custom payload built from a key
     * value array.
     *
     * @param mixed[] $payload
     */
    public static function customPayload(array $payload, string $secret): string
    {
        $tokens = new Tokens();
        return $tokens->createCustomToken($payload, $secret)->getToken();
    }

    /**
     * Validate the Json web token, check it's structure and signature. Also
     * check its expiration claim and not before claim if they are set.
     */
    public static function validate(string $token, string $secret): bool
    {
        $tokens = new Tokens();
        return $tokens->basicValidation($token, $secret);
    }

    /**
     * Return the header of the token as an associative array. You should run
     * the validate method on your token before retrieving the header.
     *
     * @return mixed[]
     */
    public static function getHeader(string $token, string $secret): array
    {
        $tokens = new Tokens();
        return $tokens->getHeader($token, $secret);
    }

    /**
     * Return the payload of the token as an associative array. You should run
     * the validate method on your token before retrieving the payload.
     *
     * @return mixed[]
     */
    public static function getPayload(string $token, string $secret): array
    {
        $tokens = new Tokens();
        return $tokens->getPayload($token, $secret);
    }

    /**
     * Factory method to return an instance of the ReallySimpleJWT\Build class.
     */
    public static function builder(): Build
    {
        $tokens = new Tokens();
        return $tokens->builder();
    }

    /**
     * Factory method to return instance of the ReallySimpleJWT\Parse class.
     */
    public static function parser(string $token, string $secret): Parse
    {
        $tokens = new Tokens();
        return $tokens->parser($token, $secret);
    }

    /**
     * Run standard validation and expiration validation against the token.
     *
     * @return bool
     */
    public static function validateExpiration(string $token, string $secret): bool
    {
        $tokens = new Tokens();
        return $tokens->validateExpiration($token, $secret);
    }

    /**
     * Run not before validation against token.
     *
     * @return bool
     */
    public static function validateNotBefore(string $token, string $secret): bool
    {
        $tokens = new Tokens();
        return $tokens->validateNotBefore($token, $secret);
    }
}
