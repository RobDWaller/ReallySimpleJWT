<?php

namespace Tests;

use ReallySimpleJWT\Token;
use ReallySimpleJWT\TokenValidator;
use ReallySimpleJWT\TokenBuilder;
use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class TokenValidatorTest extends TestCase
{
    public function testValidateSuccessful()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            54,
            'ab&7dj*9!ABC123',
            Carbon::now()->addMinutes(11)->toDateTimeString(),
            'www.mysite.com'
        );

        $this->assertTrue(
            $validator->splitToken($tokenString)
                ->validateExpiration()
                ->validateSignature('ab&7dj*9!ABC123')
        );
    }

    public function testGetPayload()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            'twelve123',
            'op*^9odP^yuoOd',
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            'www.mysite.com'
        );

        $payload = $validator->splitToken($tokenString)
            ->getPayload();

        $this->assertSame('twelve123', json_decode($payload)->user_id);
    }

    public function testGetMultiPayload()
    {
        $validator = new TokenValidator();

        $dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

        $builder = new TokenBuilder();

        $tokenString = $builder->setIssuer('http://127.0.0.1')
            ->setSecret('secret123*REVEALED')
            ->setExpiration($dateTime)
            ->addPayload(['key' => 'user_id', 'value' => 22])
            ->addPayload(['key' => 'username', 'value' => 'rob2'])
            ->addPayload(['key' => 'description', 'value' => 'A bad guy'])
            ->build();

        $validator->splitToken($tokenString)
            ->validateExpiration()
            ->validateSignature('secret123*REVEALED');

        $payload = $validator->getPayload();

        $this->assertSame('rob2', json_decode($payload)->username);

        $this->assertSame('A bad guy', json_decode($payload)->description);
    }

    public function testGetHeader()
    {
        $validator = new TokenValidator();

        $dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

        $builder = new TokenBuilder();

        $tokenString = $builder->setIssuer('http://127.0.0.1')
            ->setSecret('badG3rsAre*!*!')
            ->setExpiration($dateTime)
            ->addPayload(['key' => 'user_id', 'value' => 11])
            ->build();

        $validator->splitToken($tokenString)
            ->validateExpiration()
            ->validateSignature('badG3rsAre*!*!');

        $header = $validator->getHeader();

        $this->assertSame('HS256', json_decode($header)->alg);

        $this->assertSame('JWT', json_decode($header)->typ);
    }

    public function testValidateExpiration()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            'twelve123',
            'iHateC0c0mBer*&',
            Carbon::now()->addMinutes(2)->toDateTimeString(),
            'www.mysite.com'
        );

        $payload = $validator->splitToken($tokenString)
            ->validateExpiration();

        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
    }

    public function testValidateExpirationWithUnixTimestamp()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            'twelve123',
            'iHateC0c0mBer*&',
            Carbon::now()->addMinutes(2)->getTimestamp(),
            'www.mysite.com'
        );

        $payload = $validator->splitToken($tokenString)
            ->validateExpiration();

        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
    }

    public function testValidateExpirationWithNumber()
    {
        $validator = m::mock(TokenValidator::class);
        $validator->makePartial();
        $validator->shouldReceive('getExpiration')->once()->andReturn(
            Carbon::now()->addMinutes(2)->getTimestamp()
        );

        $payload = $validator->validateExpiration();

        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
    }

    public function testValidateExpirationWithString()
    {
        $validator = m::mock(TokenValidator::class);
        $validator->makePartial();
        $validator->shouldReceive('getExpiration')->once()->andReturn(
            Carbon::now()->addMinutes(2)->toDateTimeString()
        );

        $payload = $validator->validateExpiration();

        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage This token has expired!
     */
    public function testValidateExpirationWithNumberFail()
    {
        $validator = m::mock(TokenValidator::class);
        $validator->makePartial();
        $validator->shouldReceive('getExpiration')->once()->andReturn(
            Carbon::now()->subMinutes(2)->getTimestamp()
        );

        $validator->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage This token has expired!
     */
    public function testValidateExpirationWithStringFail()
    {
        $validator = m::mock(TokenValidator::class);
        $validator->makePartial();
        $validator->shouldReceive('getExpiration')->once()->andReturn(
            Carbon::now()->subMinutes(2)->toDateTimeString()
        );

        $validator->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage This token has expired!
     */
    public function testValidateExpirationFailure()
    {
        $validator = new TokenValidator();

        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
		eyJ1c2VyX2lkIjoyMDE5MjMsImlzcyI6Ind3dy55b3Vyc2l0ZS5jb20iLCJleHAiOiIyMDE3
		LTAyLTIzIDA5OjIyOjExIiwic3ViIjpudWxsLCJhdWQiOm51bGx9.
		Wlkt+HRQ7MIhcl6h+ECPlAArb4YhY79GsoVIEphnhlo=';

        $validator->splitToken($tokenString)
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage Bad payload object, no expiration parameter set
     */
    public function testValidateExpirationFailureBadData()
    {
        $validator = new TokenValidator();

        $tokenString = 'eyJhbGciOizI1NiIsInR5cCI6IkpXVCJ9.
		eyJ1c2VyX2lkIjoyMDE5MjMsImlzcyI6Ind3Vyc2l0ZS5jb20iLCJleHAiOiIyMDE3
		LTAyLTIzIDA5OjIyOjExIiwic3ViIsLCJhdWQiOm51bGx9.
		Wlkt+HRQ7MIhcl6h+ECPlAArb4YhY79GsoVIEphnhlo=';

        $validator->splitToken($tokenString)
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     * @expectedExceptionMessageRegExp |^The date time string \[.*\] you attempted to parse is empty\.$|
     */
    public function testValidateExpirationFailureEmptyDate()
    {
        $validator = new TokenValidator();

        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
		eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6IiJ9.
		4OGvHh_thMaNu0vc57AuiSqsn0mQYtNrSUvRa4mYt6M';

        $validator->splitToken($tokenString)
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     * @expectedExceptionMessageRegExp |^The date time string \[.*\] you attempted to parse is invalid\.$|
     */
    public function testValidateExpirationFailureBadDate()
    {
        $validator = new TokenValidator();

        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6ImhlbGxvIn0.
			yA4cawhobqrrsqDMFfcZkgj-c0KQ8ozuTlDFebTkujs';

        $validator->splitToken($tokenString)
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage Token string has invalid structure, ensure three strings seperated by dots.
     */
    public function testSplitTokenFail()
    {
        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9';

        $validator = new TokenValidator();

        $validator->splitToken($tokenString);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage Token string has invalid structure, ensure three strings seperated by dots.
     */
    public function testSplitTokenFailNoDot()
    {
        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

        $validator = new TokenValidator();

        $validator->splitToken($tokenString);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessage Token string has invalid structure, ensure three strings seperated by dots.
     */
    public function testSplitTokenFailFourDot()
    {
        $tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
			eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

        $validator = new TokenValidator();

        $validator->splitToken($tokenString);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessageRegExp |^Token signature is invalid!! Input:\s.*|
     */
    public function testValidateSignatureFail()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            734,
            'ab9OPP10&*^9',
            Carbon::now()->addMinutes(11)->toDateTimeString(),
            'www.cars.com'
        );

        $tokenString = substr($tokenString, 0, -1);

        $validator->splitToken($tokenString)
            ->validateExpiration()
            ->validateSignature('ab9OPP10&*^9');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedExceptionMessageRegExp |^Token signature is invalid!! Input:\s.*|
     */
    public function testValidateSignatureFailTwo()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            734,
            '*&123HYGhdiso*',
            Carbon::now()->addMinutes(11)->toDateTimeString(),
            'www.cars.com'
        );

        $validator->splitToken($tokenString)
            ->validateExpiration()
            ->validateSignature('*&123HYGhdi');
    }

    public function testGetPayloadDecodJson()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            326,
            'pieFace33334^',
            Carbon::now()->addMinutes(11)->toDateTimeString(),
            'www.cars.com'
        );

        $this->assertInstanceOf(\stdClass::class, $validator->splitToken($tokenString)->getPayloadDecodeJson());
        $this->assertSame(326, $validator->splitToken($tokenString)->getPayloadDecodeJson()->user_id);
    }

    public function testGetHeaderDecodJson()
    {
        $validator = new TokenValidator();

        $tokenString = Token::getToken(
            326,
            'eyes11ARE666&',
            Carbon::now()->addMinutes(11)->toDateTimeString(),
            'www.cars.com'
        );

        $this->assertInstanceOf(\stdClass::class, $validator->splitToken($tokenString)->getHeaderDecodeJson());
        $this->assertSame('HS256', $validator->splitToken($tokenString)->getHeaderDecodeJson()->alg);
    }
}
