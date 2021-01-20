<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Interfaces;

/**
 * A validation helper class which offers methods to confirm the validity of
 * a JSON Web Token along with aspects of its content.
 *
 * Error codes and messages:
 * 1: Token is invalid: Token must have three parts separated by dots.
 * 2: Audience claim does not contain provided StringOrURI.
 * 3: Signature is invalid: Signature does not match header / payload content.
 * 4: Expiration claim has expired.
 * 5: Not Before claim has not elapsed.
 * 6: Expiration claim is not set.
 * 7: Not Before claim is not set.
 * 8: Invalid payload claim: Claims must be key values of type string:mixed.
 * 9: Invalid secret: See README for more information.
 * 10: Invalid Audience claim: Must be either a string or array of strings.
 */
interface Validator
{
    /**
     * Confirm the structure of a JSON Web Token, it has three parts separated
     * by dots and complies with Base64URL standards.
     */
    public function structure(string $jwt): bool;

    /**
     * Check the validity of the JWT's expiration claim as defined in the
     * token payload. Returns false if the expiration time has surpassed the
     * current time.
     */
    public function expiration(int $expiration): bool;

    /**
     * Check the validity of the JWT's not before claim as defined in the
     * token payload. Returns false if the not before time has not surpassed
     * the current time.
     */
    public function notBefore(int $notBefore): bool;

    /**
     * Check the validity of the JWT's audience claim. The audience claim
     * defines the recipient or recipients allowed to process the token. This
     * claim can either be a StringOrURI or an array of StringOrURIs.
     *
     * @param string|string[] $audience
     */
    public function audience($audience, string $check): bool;

    /**
     * Check two signature hashes match. One signature is supplied by the token.
     * The other is newly generated from the token's header and payload. They
     * should match, if they don't someone has likely tampered with the token.
     */
    public function signature(string $generatedSignature, string $tokenSignature): bool;

    /**
     * Check the alg claim is in the list of valid algorithms. These are the
     * valid digital signatures, MAC algorithms or "none" as
     * defined in RFC 7518.
     *
     * @param string[] $validAlgorithms
     */
    public function algorithm(string $algorithm, array $validAlgorithms): bool;
}
