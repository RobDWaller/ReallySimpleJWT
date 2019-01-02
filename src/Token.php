<?php

namespace ReallySimpleJWT;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Exception\ValidateException;
use Carbon\Carbon;

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
     * Create a JSON Web Token that contains a user identifier payload.
     *
     * @param mixed $userId
     * @param string $secret
     * @param string $expiration
     * @param string $issuer
     *
     * @return string
     */
    public static function create($userId, string $secret, string $expiration, string $issuer): string
    {
        $builder = self::builder();

        return $builder->setPayloadClaim('user_id', $userId)
            ->setSecret($secret)
            ->setExpiration(Carbon::parse($expiration)->getTimestamp())
            ->setIssuer($issuer)
            ->setIssuedAt(time())
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
            $parse->validate()->validateExpiration();
            return true;
        } catch (ValidateException $e) {
            return false;
        }
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
