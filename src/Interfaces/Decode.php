<?php

namespace ReallySimpleJWT\Interfaces;

interface Decode
{
    /**
     * Decode a base64URL string to a JSON string.
     */
    public function decode(string $toDecode): array;
}