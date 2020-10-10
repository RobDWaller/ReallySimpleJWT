<?php

namespace ReallySimpleJWT\Interfaces;

interface Encode
{
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64URL compliant.
     */
    public function encode(array $toEncode): string;

    /**
     * Create the JSON Web Token signature string.
     */
    public function signature(array $header, array $payload, string $secret): string;
}