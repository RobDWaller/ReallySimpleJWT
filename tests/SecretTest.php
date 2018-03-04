<?php

namespace Tests;

use ReallySimpleJWT\Helper\Secret;
use PHPUnit\Framework\TestCase;

class SecretTest extends TestCase
{
    public function testSecret()
    {
        $this->assertTrue(Secret::validate('HELLOworldFOOBAR123*&!@%^#$'));
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\SecretException
     * @expectedExceptionMessage The secret you provided must be at least 12 characters in length.
     */
    public function testSecretLength()
    {
        Secret::validate('hello');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\SecretException
     * @expectedExceptionMessage The secret you provided must contain number characters.
     */
    public function testSecretNumbers()
    {
        Secret::validate('helloworldfoobar');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\SecretException
     * @expectedExceptionMessage The secret you provided must contain uppercase letters.
     */
    public function testSecretUpperCase()
    {
        Secret::validate('helloworldfoobar123');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\SecretException
     * @expectedExceptionMessage The secret you provided must contain lowercase letters.
     */
    public function testSecretLowerCase()
    {
        Secret::validate('HELLOWORLDFOOBAR123');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\SecretException
     * @expectedExceptionMessage The secret you provided must contain some special characters (*&!@%^#$).
     */
    public function testSecretSpecialCharacters()
    {
        Secret::validate('HELLOworldFOOBAR123');
    }
}
