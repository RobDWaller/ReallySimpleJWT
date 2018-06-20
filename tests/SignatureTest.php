<?php

namespace Tests;

use ReallySimpleJWT\Helper\Signature;
use PHPUnit\Framework\TestCase;

class SignatureTest extends TestCase
{
    public function testSignature()
    {
        $signature = new Signature('header', 'payload', '123', 'sha256');

        $signature = $signature->get();

        $this->assertNotEmpty($signature);

        $this->assertSame(
            str_replace(['=', '/', '+'], ['', '_', '-'], base64_encode(
                hash_hmac('sha256',
                    str_replace(['=', '/', '+'], ['', '_', '-'], base64_encode('header'))
                    . "." .
                    str_replace(['=', '/', '+'], ['', '_', '-'], base64_encode('payload')), '123', true)
            )),
            $signature
        );
    }
}
