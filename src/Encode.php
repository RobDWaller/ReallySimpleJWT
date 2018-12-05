<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Encode
{
    public function encode(string $toEncode): string
    {
        return $this->toBase64Url(base64_encode($toEncode));
    }

    private function toBase64Url(string $base64): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }
}
