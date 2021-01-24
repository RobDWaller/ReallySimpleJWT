<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Interface for Decode class if customisation is required.
 */
interface Decode
{
    /**
     * Decode a base64URL string to an associative array.
     *
     * @see Decode::decode()
     * @return mixed[]
     */
    public function decode(string $toDecode): array;
}
