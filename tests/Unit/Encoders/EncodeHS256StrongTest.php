<?php

declare(strict_types=1);

namespace Tests\Unit\Encoders;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Encoders\EncodeHS256Strong;
use ReallySimpleJWT\Exception\EncodeException;

class EncodeHS256StrongTest extends TestCase
{
    public function testValidateSecret(): void
    {
        $encode = new EncodeHS256Strong('Hello123$$Abc!!4538');

        $this->assertSame('HS256', $encode->getAlgorithm());
    }

    public function testValidateSecretAllSpecialCharacters(): void
    {
        $encode = new EncodeHS256Strong('Hello123*&!@%^#$4538');

        $this->assertSame('HS256', $encode->getAlgorithm());
    }

    public function testValidateSecretOtherSpecialCharacters(): void
    {
        $encode = new EncodeHS256Strong('Hello123*&£~!@%^#$4538');

        $this->assertSame('HS256', $encode->getAlgorithm());
    }

    public function testValidateSecretInvalidLength(): void
    {
        $this->expectException(EncodeException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $encode = new EncodeHS256Strong('hello');
    }

    public function testValidateSecretInvalidNumbers(): void
    {
        $this->expectException(EncodeException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $encode = new EncodeHS256Strong('helloworldfoobar');
    }

    public function testValidateSecretInvalidUppercase(): void
    {
        $this->expectException(EncodeException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $encode = new EncodeHS256Strong('helloworldfoobar123');
    }

    public function testValidateSecretInvalidLowercase(): void
    {
        $this->expectException(EncodeException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $encode = new EncodeHS256Strong('HELLOWORLDFOOBAR123');
    }

    public function testValidateSecretSpecialCharacters(): void
    {
        $this->expectException(EncodeException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $encode = new EncodeHS256Strong('HELLOworldFOOBAR123');
    }
}
