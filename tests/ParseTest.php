<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Exception\ValidateException;
use ReflectionMethod;

class ParseTest extends TestCase
{
    public function testParseParse(): void
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, '127.0.0.1'), 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parsed::class, $parse->parse());
    }

    public function testParseIssuer(): void
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $result = $parse->parse();

        $this->assertSame('localhost', $result->getPayload()['iss']);
    }

    public function testParseSplitToken(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $parse = new Parse(
            new Jwt($token, 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'splitToken');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($result[0], 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
        $this->assertSame($result[1], 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
        $this->assertSame($result[2], 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    }

    public function testParseGetPayload(): void
    {
        $token = new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56');

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getPayload');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame(explode('.', $token->getToken())[1], $result);
    }

    public function testParseGetHeader(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        '--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s';

        $token = new Jwt($token, 'foo1234He$$llo56');

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getHeader');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame(explode('.', $token->getToken())[0], $result);
    }

    public function testParseValidate(): void
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validate());
    }

    public function testParseValidateInvalidStructure(): void
    {
        $parse = new Parse(
            new Jwt('hello', 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Token is invalid.');
        $this->expectExceptionCode(1);

        $parse->validate();
    }

    public function testParseValidateBadTokenGoodStructure(): void
    {
        $parse = new Parse(
            new Jwt('hello.hello.hello', 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $parse->validate();
    }

    public function testParseValidateInvalidSignature(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbT';

        $parse = new Parse(
            new Jwt($token, 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $parse->validate();
    }

    public function testGetSignature(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        '--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s';

        $parse = new Parse(
            new Jwt($token, 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getSignature');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', $result);
    }

    public function testParseValidateExpiration(): void
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'Hoo1234%&HePPo99', time() + 300, 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateExpiration());
    }

    public function testParseValidateExpirationInvalid(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.' .
        'FruqGMjzi7Ql7a8WJeMz6f6G5UeUQcy5kauLmeO8Ksc';

        $parse = new Parse(
            new Jwt($token, 'Hoo1234%&HePPo99'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);

        $parse->validateExpiration();
    }

    public function testParseValidateExpirationInvalidTwo(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        '--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s';

        $parse = new Parse(
            new Jwt($token, 'Hoo1234%&HePPo99'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim is not set.');
        $this->expectExceptionCode(6);

        $parse->validateExpiration();
    }

    public function testGetExpiration(): void
    {
        $timestamp = time() + 300;

        $parse = new Parse(
            new Jwt(Token::create(1, 'Hoo1234%&HePPo99', $timestamp, 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getExpiration');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($timestamp, $result);
    }

    public function testGetNotBefore(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getNotBefore');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($time, $result);
    }

    public function testParseValidateNotBefore(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() - 10)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateNotBefore());
    }

    public function testParseValidateNotBeforeInvalid(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);

        $parse->validateNotBefore();
    }

    public function testParseValidateNotBeforeNotSet(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setExpiration(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim is not set.');
        $this->expectExceptionCode(7);

        $parse->validateNotBefore();
    }

    public function testParseValidateExpirationNotSet(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim is not set.');
        $this->expectExceptionCode(6);

        $parse->validateExpiration();
    }

    public function testDecodePayload(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'decodePayload');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($time, $result['nbf']);
    }

    public function testDecodeHeader(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'decodeHeader');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('JWT', $result['typ']);
    }

    public function testValidateSignature(): void
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->assertNull($method->invoke($parse));
    }

    public function testValidateSignatureBadTokenGoodStructure(): void
    {
        $parse = new Parse(
            new Jwt('hello.hello.hello', 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $method->invoke($parse);
    }

    public function testValidateSignatureEmptyToken(): void
    {
        $parse = new Parse(
            new Jwt('', 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $method->invoke($parse);
    }

    public function testValidateSignatureBadTokenStructure(): void
    {
        $parse = new Parse(
            new Jwt('car', 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $method->invoke($parse);
    }

    public function testValidateSignatureInvalidSignature(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbT';

        $parse = new Parse(
            new Jwt($token, 'foo1234He$$llo56'),
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $method->invoke($parse);
    }

    public function testParseRandomTokenNoSecret(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbWVzIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'BtrZtcOwhxY9BuV0-Eqc7CybKiWqgr6Y5jFVr15zcFk';

        $parse = new Parse(
            new Jwt($token, ''),
            new Validate(),
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getSubject(), "1234567890");
        $this->assertSame($parsed->getPayload()['name'], 'James');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    public function testParseRandomTokenInvalidSecret(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJqdGkiOiJSVzg0LTIwMTkwMTA5IiwibmFtZSI6IlJvYiIsImlhdCI6MTUxNjIzOTAyMn0.' .
        'JojSqQXc-nsiongo1I33lsd7eJZ9WbMoZn65_LL1U8A';

        $parse = new Parse(
            new Jwt($token, 'hello'),
            new Validate(),
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getJwtId(), "RW84-20190109");
        $this->assertSame($parsed->getPayload()['name'], 'Rob');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    public function testParseRandomTokenValidSecret(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.' .
        'dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio';

        $parse = new Parse(
            new Jwt($token, '123$car*PARK456'),
            new Validate(),
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getAudience(), "https://google.com");
        $this->assertSame($parsed->getPayload()['name'], 'Chris');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    public function testParseRandomTokenExpirationException(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJleHAiOjE1MTYyMzkwMjJ9.' .
        'Pzio_7YdNC2NCcBBmVjRlTTgC4RNofEGYWm9ygx41JQ';

        $parse = new Parse(
            new Jwt($token, '123$car*PARK456'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);

        $parse->validate()
            ->validateExpiration();
    }

    public function testParseRandomTokenExpirationNotSetException(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.' .
        'dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio';

        $parse = new Parse(
            new Jwt($token, '123$car*PARK456'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim is not set.');
        $this->expectExceptionCode(6);

        $parse->validate()
            ->validateExpiration();
    }

    public function testParseRandomTokenNotBeforeNotSetException(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.' .
        'dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio';

        $parse = new Parse(
            new Jwt($token, '123$car*PARK456'),
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim is not set.');
        $this->expectExceptionCode(7);

        $parse->validate()
            ->validateNotBefore();
    }

    public function testGetAudience(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience('https://example.com')
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getAudience');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($result, 'https://example.com');
    }

    public function testGetAudienceArray(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience(['https://example.com', 'https://test.com'])
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getAudience');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($result, ['https://example.com', 'https://test.com']);
    }

    public function testGetAudienceFail(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getAudience');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim is not set.');
        $this->expectExceptionCode(11);
        $method->invoke($parse);
    }

    public function testParseValidateAudience(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience('https://example.com')
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateAudience('https://example.com'));
    }

    public function testParseValidateAudienceArray(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience(['https://example.com', 'https://test.com'])
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateAudience('https://test.com'));
    }

    public function testParseValidateAudienceFail(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience('https://example.com')
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim does not contain provided StringOrURI.');
        $this->expectExceptionCode(2);
        $parse->validateAudience('https://example.co.uk');
    }

    public function testParseValidateAudienceArrayFail(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience(['https://example.com', 'https://test.com'])
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim does not contain provided StringOrURI.');
        $this->expectExceptionCode(2);
        $parse->validateAudience('https://google.co.uk');
    }

    public function testParseValidateAlgorithm(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience(['https://example.com', 'https://test.com'])
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateAlgorithm());
    }

    public function testParseValidateAlgorithmFail(): void
    {
        $token = new Jwt(
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM" .
            "5MDIyfQ.Brp7tDCUj3wlZtF6a15KW0A7wLJbnDLOFky03GY9vSdEYo-RlwFCIqpzFV0hHsH5_A7pA28yrRFPqyTSsumZfQ",
            "Hello"
        );

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim is not valid.');
        $this->expectExceptionCode(12);
        $parse->validateAlgorithm();
    }

    public function testParseGetAlgorithm(): void
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setAudience(['https://example.com', 'https://test.com'])
            ->build();

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getAlgorithm');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($result, "HS256");
    }

    public function testParseGetAlgorithmFail(): void
    {
        $token = new Jwt(
            "ewogICJ0eXAiOiAiSldUIgp9.ewogICJleHAiOiAxMjM0NQp9.ewogICJ0eXAiOiAiSldUIgp9",
            "Hello"
        );

        $parse = new Parse(
            $token,
            new Validate(),
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getAlgorithm');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim is not set.');
        $this->expectExceptionCode(13);
        $method->invoke($parse);
    }
}
