<?php

namespace Test;

use ReflectionMethod;
use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use Carbon\Carbon;

class ValidateTest extends TestCase
{
    public function testValidate()
    {
        $jwt = new Jwt('Hello');

        $validate = new Validate($jwt);

        $this->assertInstanceOf(Validate::class, $validate);
    }

    public function testValidateTokenStructure()
    {
        $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9ncyIsImlhdCI6MTUxNjIzOTAyMn0.-wvw8Qad0enQkwNhG2j-GCT-7PbrMN_gtUwOKZTu54M');

        $validate = new Validate($jwt);

        $method = new ReflectionMethod(Validate::class, 'tokenStructure');
        $method->setAccessible(true);

        $result = $method->invoke($validate);

        $this->assertTrue($result);
    }

    public function testValidateTokenStructureWithRSJWT()
    {
        $jwt = new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'));

        $validate = new Validate($jwt);

        $method = new ReflectionMethod(Validate::class, 'tokenStructure');
        $method->setAccessible(true);

        $result = $method->invoke($validate);

        $this->assertTrue($result);
    }

    public function testValidateTokenStructureInvalid()
    {
        $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');

        $validate = new Validate($jwt);

        $method = new ReflectionMethod(Validate::class, 'tokenStructure');
        $method->setAccessible(true);

        $result = $method->invoke($validate);

        $this->assertFalse($result);
    }
}
