<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Token;

class ValidateTest extends TestCase
{
    public function testValidate(): void
    {
        $validate = new Validate();

        $this->assertInstanceOf(Validate::class, $validate);
    }

    public function testValidateStructure(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9ncyIsImlhdCI6MTUxNjIzOTAyMn0.' .
        '-wvw8Qad0enQkwNhG2j-GCT-7PbrMN_gtUwOKZTu54M';

        $validate = new Validate();

        $this->assertTrue($validate->structure($token));
    }

    public function testValidateStructureWithRSJWT(): void
    {
        $token = Token::create(1, 'foo1234He$$llo56', time() + 300, '127.0.0.1');

        $validate = new Validate();

        $this->assertTrue($validate->structure($token));
    }

    public function testValidateStructureInvalid(): void
    {
        $validate = new Validate();

        $this->assertFalse($validate->structure('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
    }

    public function testValidateExpiration(): void
    {
        $validate = new Validate();

        $this->assertTrue($validate->expiration(time() + 10));
    }

    public function testValidateExpirationOld(): void
    {
        $validate = new Validate();

        $this->assertFalse($validate->expiration(time() - 10));
    }

    public function testValidateSignature(): void
    {
        $validate = new Validate();
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertTrue($validate->signature($signature, 'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateSignatureInvalid(): void
    {
        $validate = new Validate();
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertFalse($validate->signature($signature, 'tsVs-jHudH5hVZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateSignatureInvalidTwo(): void
    {
        $validate = new Validate();
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "Jane Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertFalse($validate->signature($signature, 'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateNotBefore(): void
    {
        $validate = new Validate();

        $this->assertTrue($validate->notBefore(time() - 10));
    }

    public function testValidateNotFalse(): void
    {
        $validate = new Validate();

        $this->assertFalse($validate->notBefore(time() + 10));
    }

    public function testValidateAudience(): void
    {
        $validate = new Validate();

        $audience = 'https://example.com';
        $check = 'https://example.com';

        $this->assertTrue($validate->audience($audience, $check));
    }

    public function testValidateAudienceFalse(): void
    {
        $validate = new Validate();

        $audience = 'https://example.com';
        $check = 'example.com';

        $this->assertFalse($validate->audience($audience, $check));
    }

    public function testValidateAudienceArray(): void
    {
        $validate = new Validate();

        $audience = ['https://example.com', 'https://test.com'];
        $check = 'https://example.com';

        $this->assertTrue($validate->audience($audience, $check));
    }

    public function testValidateAudienceArrayFalse(): void
    {
        $validate = new Validate();

        $audience = ['https://example.com', 'https://test.com'];
        $check = 'example.com';

        $this->assertFalse($validate->audience($audience, $check));
    }

    public function testValidateAudienceIntFalse(): void
    {
        $validate = new Validate();

        $audience = 2;
        $check = 'example.com';

        $this->assertFalse($validate->audience($audience, $check));
    }

    public function testValidateAlgorithm(): void
    {
        $validate = new Validate();

        $algorithm = "HS256";

        $this->assertTrue($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmNone(): void
    {
        $validate = new Validate();

        $algorithm = "none";

        $this->assertTrue($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmFail(): void
    {
        $validate = new Validate();

        $algorithm = "HB256";

        $this->assertFalse($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmCustom(): void
    {
        $validate = new Validate();

        $algorithm = "HS384";

        $this->assertTrue($validate->algorithm($algorithm, ["HS384"]));
    }

    public function testValidateAlgorithmCustomFail(): void
    {
        $validate = new Validate();

        $algorithm = "HB384";

        $this->assertFalse($validate->algorithm($algorithm, ["HS384"]));
    }

    public function testValidateAlgorithmCustomStandard(): void
    {
        $validate = new Validate();

        $algorithm = "HS256";

        $this->assertTrue($validate->algorithm($algorithm, ["HS384"]));
    }
}
