<?php

declare(strict_types=1);

namespace Tests\Unit\Helper;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Helper\Validator;

class ValidatorTest extends TestCase
{
    public function testValidateExpiration(): void
    {
        $validate = new Validator();

        $this->assertTrue($validate->expiration(time() + 10));
    }

    public function testValidateExpirationOld(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->expiration(time() - 10));
    }

    public function testValidateSignature(): void
    {
        $validate = new Validator();

        $this->assertTrue($validate->signature('hello', 'hello'));
    }

    public function testValidateSignatureInvalid(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->signature('hello', 'world'));
    }

    public function testValidateNotBefore(): void
    {
        $validate = new Validator();

        $this->assertTrue($validate->notBefore(time() - 10));
    }

    public function testValidateNotBeforeFalse(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->notBefore(time() + 10));
    }

    public function testValidateNotBeforeZero(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->notBefore(0));
    }

    public function testValidateAudience(): void
    {
        $validate = new Validator();

        $audience = 'https://example.com';
        $check = 'https://example.com';

        $this->assertTrue($validate->audience($audience, $check));
    }

    public function testValidateAudienceFalse(): void
    {
        $validate = new Validator();

        $audience = 'https://example.com';
        $check = 'example.com';

        $this->assertFalse($validate->audience($audience, $check));
    }

    public function testValidateAudienceArray(): void
    {
        $validate = new Validator();

        $audience = ['https://example.com', 'https://test.com'];
        $check = 'https://example.com';

        $this->assertTrue($validate->audience($audience, $check));
    }

    public function testValidateAudienceArrayFalse(): void
    {
        $validate = new Validator();

        $audience = ['https://example.com', 'https://test.com'];
        $check = 'example.com';

        $this->assertFalse($validate->audience($audience, $check));
    }

    public function testValidateAlgorithm(): void
    {
        $validate = new Validator();

        $algorithm = "HS256";

        $this->assertTrue($validate->algorithm($algorithm, ["HS256"]));
    }

    public function testValidateAlgorithmFail(): void
    {
        $validate = new Validator();

        $algorithm = "HS256";

        $this->assertFalse($validate->algorithm($algorithm, ["HS384"]));
    }

    public function testValidateAlgorithmFailEmpty(): void
    {
        $validate = new Validator();

        $algorithm = "HS256";

        $this->assertFalse($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmList(): void
    {
        $validate = new Validator();

        $algorithm = "HS384";

        $this->assertTrue($validate->algorithm($algorithm, ["HS256", "HS384"]));
    }
}
