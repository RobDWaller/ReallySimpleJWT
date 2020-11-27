<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Signature as SignatureInterface;
use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Helper\JsonEncoder;

class Signature implements SignatureInterface
{
    use JsonEncoder;

    private Encode $encode;

    public function __construct(Encode $encode)
    {
        $this->encode = $encode;
    }

    public function make(array $header, array $payload, string $secret): string
    {
        return $this->encode->signature(
            $header,
            $payload,
            $secret
        );
    }
}
