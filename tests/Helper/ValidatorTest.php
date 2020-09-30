<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Token;

class ValidatorTest extends TestCase
{
    public function testValidateStructure(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9ncyIsImlhdCI6MTUxNjIzOTAyMn0.' .
        '-wvw8Qad0enQkwNhG2j-GCT-7PbrMN_gtUwOKZTu54M';

        $validate = new Validator();

        $this->assertTrue($validate->structure($token));
    }

    public function testValidateStructureInvalid(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->structure('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
    }

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
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertTrue($validate->signature($signature, 'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateSignatureInvalid(): void
    {
        $validate = new Validator();
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertFalse($validate->signature($signature, 'tsVs-jHudH5hVZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateSignatureInvalidTwo(): void
    {
        $validate = new Validator();
        $encode = new Encode();

        $header = json_encode(json_decode('{"alg": "HS256", "typ": "JWT"}'));
        $payload = json_encode(json_decode('{"sub": "1234567890", "name": "Jane Doe", "iat": 1516239022}'));

        $signature = $encode->signature(!$header ? '' : $header, !$payload ? '' : $payload, 'foo1234He$$llo56');

        $this->assertFalse($validate->signature($signature, 'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbTI'));
    }

    public function testValidateNotBefore(): void
    {
        $validate = new Validator();

        $this->assertTrue($validate->notBefore(time() - 10));
    }

    public function testValidateNotFalse(): void
    {
        $validate = new Validator();

        $this->assertFalse($validate->notBefore(time() + 10));
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

        $this->assertTrue($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmNone(): void
    {
        $validate = new Validator();

        $algorithm = "none";

        $this->assertTrue($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmFail(): void
    {
        $validate = new Validator();

        $algorithm = "HB256";

        $this->assertFalse($validate->algorithm($algorithm, []));
    }

    public function testValidateAlgorithmCustom(): void
    {
        $validate = new Validator();

        $algorithm = "HS384";

        $this->assertTrue($validate->algorithm($algorithm, ["HS384"]));
    }

    public function testValidateAlgorithmCustomFail(): void
    {
        $validate = new Validator();

        $algorithm = "HB384";

        $this->assertFalse($validate->algorithm($algorithm, ["HS384"]));
    }

    public function testValidateAlgorithmCustomStandard(): void
    {
        $validate = new Validator();

        $algorithm = "HS256";

        $this->assertTrue($validate->algorithm($algorithm, ["HS384"]));
    }
}
