<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Interfaces;

/**
 * Interface for Validator classes to allow developers to implement custom token
 * validation if required.
 */
interface Validator
{
    /**
     * Check the validity of the JWT's expiration claim.
     *
     * @see Helper\Validator::expiration()
     */
    public function expiration(int $expiration): bool;

    /**
     * Check the validity of the JWT's not before claim.
     *
     * @see Helper\Validator::notBefore()
     */
    public function notBefore(int $notBefore): bool;

    /**
     * Check the validity of the JWT's audience claim.
     *
     * @see Helper\Validator::audience()
     * @param string|string[] $audience
     */
    public function audience($audience, string $check): bool;

    /**
     * Check the token signature and generated signature match.
     *
     * @see Helper\Validator::signature()
     */
    public function signature(string $generatedSignature, string $tokenSignature): bool;

    /**
     * Check the alg claim is in the list of valid algorithms.
     *
     * @see Helper\Validator::algorithm()
     * @param string[] $validAlgorithms
     */
    public function algorithm(string $algorithm, array $validAlgorithms): bool;
}
