<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * This is an interface for the ReallySimpleJWT\Encode class, it defines what
 * public methods must be available and what they must return. Custom encoding
 * class must implement this interface to work with the ReallySimpleJWT library.
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
interface EncodeInterface
{
    /**
     * Get the algorithm used to encode the signature string. This will also
     * act as the alg claim in the token header.
     */
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64 URL compliant.
     */
    public function encode(string $toEncode): string;

    /**
     * Decode a base64 URL string to a JSON string.
     */
    public function decode(string $toDecode): string;

    /**
     * Create the JSON Web Token signature string.
     */
    public function signature(string $header, string $payload, string $secret): string;
}
