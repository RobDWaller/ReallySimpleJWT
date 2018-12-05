<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Encode
{
    public function encode(string $toEncode): string
    {
        return base64_encode($toEncode);
    }
}
