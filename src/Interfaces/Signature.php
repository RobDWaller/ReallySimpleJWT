<?php

namespace ReallySimpleJWT\Interfaces;

interface Signature
{
    public function make(array $header, array $payload, string $secret): string;
}