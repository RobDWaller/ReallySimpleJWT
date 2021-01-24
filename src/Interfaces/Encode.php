<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Interface for Encode classes, enables custom signature encoding dependent
 * on security requirements.
 */
interface Encode
{
    /**
     * Retrieve the algorithm used to encode the signature.
     *
     * @see Encoders\EncodeHS256::getAlgorithm()
     */
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64URL compliant.
     *
     * @see Encoders\EncodeHS256::encode()
     * @param mixed[] $toEncode
     */
    public function encode(array $toEncode): string;

    /**
     * Create the JSON Web Token signature string.
     *
     * @see Encoders\EncodeHS256::signature()
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function signature(array $header, array $payload, string $secret): string;
}
