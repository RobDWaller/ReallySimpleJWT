<?php

namespace ReallySimpleJWT\Interfaces;

interface Decode
{
    /**
     * Decode a base64URL string to a JSON string.
     *
     * @return mixed[]
     */
    public function decode(string $toDecode): array;
}
