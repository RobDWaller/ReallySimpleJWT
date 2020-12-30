<?php

namespace ReallySimpleJWT\Interfaces;

interface Encode
{
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64URL compliant.
     * 
     * @param mixed[] $toEncode
     */
    public function encode(array $toEncode): string;

    /**
     * Create the JSON Web Token signature string.
     * 
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function signature(array $header, array $payload, string $secret): string;
}
