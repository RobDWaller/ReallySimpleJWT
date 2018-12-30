<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

/**
 * A validation helper class which offers methods to cofirm the validity of
 * a JSON Web Token along with aspects of its content.
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
class Validate
{
    /**
     * Confirm the structure of a JSON Web Token, it has three parts separated
     * by dots and complies with Base64 URL standards.
     *
     * @param string $jwt
     * @return bool
     */
    public function structure(string $jwt): bool
    {
        return preg_match(
            '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
            $jwt
        ) === 1;
    }

    /**
     * Check the validity of the JWT's expiration claim as defined in the
     * token payload. Returns false if the expiration time has surpassed the
     * current time.
     *
     * @param int $expiration
     * @return bool
     * @todo This should not be greater or equal to, just greater.
     */
    public function expiration(int $expiration): bool
    {
        return $expiration >= time();
    }

    /**
     * Check the validity of the JWT's not before claim as defined in the
     * token payload. Returns false if the not before time has not surpassed
     * the current time.
     *
     * @param int $notBefore
     * @return bool
     * @todo This should not be less or equal to, just less.
     */
    public function notBefore(int $notBefore): bool
    {
        return $notBefore <= time();
    }

    /**
     * Check to signature hashes match. One signature is supplied by the token.
     * The other is newly gernated from the token's header and payload. They
     * should match if they don't someone has likely tampered with the token.
     */
    public function signature(string $signature, string $comparison): bool
    {
        return hash_equals($signature, $comparison);
    }

    /**
     * Validate the secret used to secure the token signature is strong enough.
     * It should contain a number, upper and lowercase letters, and a special
     * character. It should be at least 12 charachers in length.
     *
     * The regex here uses...
     *
     * @param string $secret
     * @return bool
     * @todo write test to check it still works with other special characters
     * maybe requires a signature generation test too.
     */
    public function secret(string $secret): bool
    {
        if (!preg_match(
            '/^.*(?=.{12,}+)(?=.*[0-9]+)(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[\*&!@%\^#\$]+).*$/',
            $secret
        )) {
            return false;
        }

        return true;
    }
}
