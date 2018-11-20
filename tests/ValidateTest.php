<?php

namespace Test;

use ReflectionMethod;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;

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
}
