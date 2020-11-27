<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Signature as SignatureInterface;
use ReallySimpleJWT\Interfaces\Encoder;
use ReallySimpleJWT\Helper\JsonEncoder;

class Signature implements SignatureInterface
{
    use JsonEncoder;
    
    private Encoder $encode;

    public function __construct(Encoder $encode)
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
