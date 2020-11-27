<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Signature;
use ReallySimpleJWT\Encoders\EncodeHs256;
use Tests\Fixtures\Tokens;

class SignatureTest extends TestCase
{

    public function testMake()
    {
        $encode = $this->createStub(EncodeHs256::class);
        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, Tokens::SECRET)
            ->willReturn(Tokens::SIGNATURE);

        $signature = new Signature($encode);

        $result = $signature->make(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, Tokens::SECRET);

        $this->assertSame(Tokens::SIGNATURE, $result);
    }
}
