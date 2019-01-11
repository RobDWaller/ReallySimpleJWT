<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
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
     * Create a JSON Web Token that contains a user identifier and
     * expiration payload.
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
     * Validate a JSON Web Token's expiration and signature.
     *
     * @param string $token
     * @param string $secret
     *
     * @return bool
     */
    public static function validate(string $token, string $secret): bool
    {
        $parse = self::parser($token, $secret);

        try {
            $parse->validate()
                ->validateExpiration()
                ->validateNotBefore();
        } catch (ValidateException $e) {
            if (in_array($e->getCode(), [1, 2, 3, 4, 5], true)) {
                return false;
            }
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
        return new Build('JWT', new Validate(), new Encode());
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
}
