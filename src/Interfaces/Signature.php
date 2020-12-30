<?php

namespace ReallySimpleJWT\Interfaces;

interface Signature
{
    /**
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function make(array $header, array $payload, string $secret): string;
}
