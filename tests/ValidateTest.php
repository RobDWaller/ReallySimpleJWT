<?php

namespace Test;

use ReflectionMethod;
use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Token;
use Carbon\Carbon;

class ValidateTest extends TestCase
{
    public function testValidate()
    {
        $validate = new Validate();

        $this->assertInstanceOf(Validate::class, $validate);
    }

    public function testValidateTokenStructure()
    {
        $validate = new Validate();

        $this->assertTrue($validate->tokenStructure('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9ncyIsImlhdCI6MTUxNjIzOTAyMn0.-wvw8Qad0enQkwNhG2j-GCT-7PbrMN_gtUwOKZTu54M'));
    }

    public function testValidateTokenStructureWithRSJWT()
    {
        $token = Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1');

        $validate = new Validate();

        $this->assertTrue($validate->tokenStructure($token));
    }

    public function testValidateTokenStructureInvalid()
    {
        $validate = new Validate();

        $this->assertFalse($validate->tokenStructure('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
    }

    public function testValidateExpiration()
    {
        $validate = new Validate();

        $this->assertTrue($validate->expiration(time() + 10));
    }
}
