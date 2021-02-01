<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Interfaces\Secret as SecretInterface;

class SecretTest extends TestCase
{
    public function testSecret(): void
    {
        $secret = new Secret();

        $this->assertInstanceOf(Secret::class, $secret);
        $this->assertInstanceOf(SecretInterface::class, $secret);
    }

    public function testValidateSecret(): void
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123$$Abc!!4538'));
    }

    public function testValidateSecretAllSpecialCharacters(): void
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123*&!@%^#$4538'));
    }

    public function testValidateSecretOtherSpecialCharacters(): void
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123*&£~!@%^#$4538'));
    }

    public function testValidateSecretInvalidLength(): void
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('hello'));
    }

    public function testValidateSecretInvalidNumbers(): void
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('helloworldfoobar'));
    }

    public function testValidateSecretInvalidUppercase(): void
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('helloworldfoobar123'));
    }

    public function testValidateSecretInvalidLowercase(): void
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('HELLOWORLDFOOBAR123'));
    }

    public function testValidateSecretSpecialCharacters(): void
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('HELLOworldFOOBAR123'));
    }
}
