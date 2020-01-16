<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Interfaces\Secret as SecretInterface;

class SecretTest extends TestCase
{
    public function testSecret()
    {
        $secret = new Secret();

        $this->assertInstanceOf(Secret::class, $secret);
        $this->assertInstanceOf(SecretInterface::class, $secret);
    }

    public function testValidateSecret()
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123$$Abc!!4538'));
    }

    public function testValidateSecretAllSpecialCharacters()
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123*&!@%^#$4538'));
    }

    public function testValidateSecretOtherSpecialCharacters()
    {
        $secret = new Secret();

        $this->assertTrue($secret->validate('Hello123*&£~!@%^#$4538'));
    }

    public function testValidateSecretInvalidLength()
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('hello'));
    }

    public function testValidateSecretInvalidNumbers()
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('helloworldfoobar'));
    }

    public function testValidateSecretInvalidUppercase()
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('helloworldfoobar123'));
    }

    public function testValidateSecretInvalidLowercase()
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('HELLOWORLDFOOBAR123'));
    }

    public function testValidateSecretSpecialCharacters()
    {
        $secret = new Secret();

        $this->assertFalse($secret->validate('HELLOworldFOOBAR123'));
    }
}
