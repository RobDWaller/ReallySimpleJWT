<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Exception\ValidateException;

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
     * @param string $secret
     * @param int $expiration
     * @param string $issuer
     *
     * @return string
     */
    public static function create($userId, string $secret, int $expiration, string $issuer): string
    {
        $builder = self::builder();

        return $builder->setPayloadClaim('user_id', $userId)
            ->setSecret($secret)
            ->setExpiration($expiration)
            ->setIssuer($issuer)
            ->setIssuedAt(time())
            ->build()
            ->getToken();
    }

    /**
     * Create a JSON Web Token with a custom payload built from a key
     * value array.
     *
     * @param array $payload
     *
     * @return string
     */
    public static function customPayload(array $payload, string $secret): string
    {
        $builder = self::builder();

        foreach ($payload as $key => $value) {
            if (is_int($key)) {
                throw new ValidateException('Invalid payload claim.', 8);
            }

            $builder->setPayloadClaim($key, $value);
        }

        return $builder->setSecret($secret)
            ->build()
            ->getToken();
    }

    /**
     * Validate the Json web token, check it's structure and signature. Also
     * check its expiration claim and not before claim if they are set.
     *
     * @param string $token
     * @param string $secret
     *
     * @return bool
     */
    public static function validate(string $token, string $secret): bool
    {
        $parse = self::parser($token, $secret);

        if (!self::validateWithExpiration($parse)) {
            return false;
        }

        if (!self::validateNotBefore($parse)) {
            return false;
        }

        return true;
    }

    /**
     * Return the header of the token as an associative array. You should run
     * the validate method on your token before retrieving the header.
     *
     * @param string $token
     *
     * @return array
     */
    public static function getHeader(string $token, string $secret): array
    {
        $parser = self::parser($token, $secret);

        return $parser->validate()->parse()->getHeader();
    }

    /**
     * Return the payload of the token as an associative array. You should run
     * the validate method on your token before retrieving the payload.
     *
     * @param string $token
     *
     * @return array
     */
    public static function getPayload(string $token, string $secret): array
    {
        $parser = self::parser($token, $secret);

        return $parser->validate()->parse()->getPayload();
    }

    /**
     * Factory method to return an instance of the ReallySimpleJWT\Build class.
     *
     * @return Build
     */
    public static function builder(): Build
    {
        return new Build('JWT', new Validate(), new Secret(), new Encode());
    }

    /**
     * Factory method to return instance of the ReallySimpleJWT\Parse class.
     *
     * @return Parse
     */
    public static function parser(string $token, string $secret): Parse
    {
        $jwt = new Jwt($token, $secret);

        return new Parse($jwt, new Validate(), new Encode());
    }

    /**
     * Run standard validation and expiration validation against the token.
     *
     * @param Parse $parse
     * @return bool
     */
    private static function validateWithExpiration(Parse $parse): bool
    {
        try {
            $parse->validate()
                ->validateExpiration();
        } catch (ValidateException $e) {
            if (in_array($e->getCode(), [1, 2, 3, 4], true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Run not before validation against token.
     *
     * @param Parse $parse
     * @return bool
     */
    private static function validateNotBefore(Parse $parse): bool
    {
        try {
            $parse->validateNotBefore();
        } catch (ValidateException $e) {
            if ($e->getCode() === 5) {
                return false;
            }
        }

        return true;
    }
}
