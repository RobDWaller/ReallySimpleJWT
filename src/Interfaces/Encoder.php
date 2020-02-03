<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Enable the custom encoding and decoding of JSON Web Tokens.
 *
 * @todo remove decode method and separate into own decode class. 4.0.0 fix.
 */
interface Encoder
{
    /**
     * Get the algorithm used to encode the signature string.
     */
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64URL compliant.
     */
    public function encode(string $toEncode): string;

    /**
     * Decode a base64URL string to a JSON string.
     */
    public function decode(string $toDecode): string;

    /**
     * Create the JSON Web Token signature string.
     */
    public function signature(string $header, string $payload, string $secret): string;
}
