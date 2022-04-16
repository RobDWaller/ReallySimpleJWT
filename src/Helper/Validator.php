<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Interfaces\Validator as ValidatorInterface;

/**
 * A validation helper class which offers methods to confirm the validity of
 * a JSON Web Token along with aspects of its content.
 */
class Validator implements ValidatorInterface
{
    /**
     * Check the validity of the JWT's expiration claim as defined in the
     * token payload. Returns false if the current time has surpassed the
     * expiration time. Time = 100 and Expiration = 99 token has expired.
     */
    public function expiration(int $expiration): bool
    {
        return $expiration > time();
    }

    /**
     * Check the validity of the JWT's not before claim as defined in the
     * token payload. Returns false if the current time has not surpassed
     * the not before time. Time = 100 and NotBefore = 101 token is not usable.
     */
    public function notBefore(int $notBefore): bool
    {
        return $notBefore !== 0 && $notBefore <= time();
    }

    /**
     * Check the validity of the JWT's audience claim. The audience claim
     * defines the recipient or recipients allowed to process the token. This
     * claim can either be a StringOrURI or an array of StringOrURIs.
     *
     * @param string|string[] $audience
     */
    public function audience($audience, string $check): bool
    {
        if (is_array($audience)) {
            return in_array($check, $audience);
        }

        return $audience === $check;
    }

    /**
     * Check two signature hashes match. One signature is supplied by the token.
     * The other is newly generated from the token's header and payload. They
     * should match, if they don't someone has likely tampered with the token.
     */
    public function signature(string $generatedSignature, string $tokenSignature): bool
    {
        return hash_equals($generatedSignature, $tokenSignature);
    }

    /**
     * Check the alg claim is in the list of valid algorithms. These are the
     * valid digital signatures, MAC algorithms or "none" as
     * defined in RFC 7518.
     *
     * @param string[] $validAlgorithms
     */
    public function algorithm(string $algorithm, array $validAlgorithms): bool
    {
        return in_array($algorithm, $validAlgorithms);
    }
}
