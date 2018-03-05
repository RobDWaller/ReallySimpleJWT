<?php

namespace Tests;

use ReallySimpleJWT\TokenBuilder;
use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Token;

class TokenBuilderTest extends TestCase
{
    public function testGetHash()
    {
        $builder = new TokenBuilder();

        $this->assertNotEmpty($builder->getHash());
    }

    public function testGetType()
    {
        $builder = new TokenBuilder();

        $this->assertNotEmpty($builder->getType());
    }

    public function testGetHeader()
    {
        $builder = new TokenBuilder();

        $header = $builder->getHeader();

        $this->assertNotEmpty($header);

        $this->assertEquals("HS256", json_decode($header)->alg);

        $this->assertEquals("JWT", json_decode($header)->typ);
    }

    public function testSetSecret()
    {
        $builder = new TokenBuilder();

        $secret = $builder->setSecret('abcDEFhij123*');

        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $secret);

        $this->assertEquals('abcDEFhij123*', $secret->getSecret());
    }

    public function testSetExpiration()
    {
        $builder = new TokenBuilder();

        $expiration = $builder->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString());

        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $expiration);

        $this->assertInstanceOf('Carbon\Carbon', $expiration->getExpiration());
    }

    public function testSetIssuer()
    {
        $builder = new TokenBuilder();

        $issuer = $builder->setIssuer('http://127.0.0.1');

        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $issuer);

        $this->assertEquals('http://127.0.0.1', $issuer->getIssuer());
    }

    public function testGetPayload()
    {
        $dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

        $builder = new TokenBuilder();

        $payload = $builder->setIssuer('http://127.0.0.1')
            ->setExpiration($dateTime)
            ->addPayload(['key' => 'user_id', 'value' => 2]);

        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $payload);

        $payload = $payload->getPayload();

        $this->assertNotEmpty($payload);

        $this->assertEquals(2, json_decode($payload)->user_id);

        $this->assertEquals("http://127.0.0.1", json_decode($payload)->iss);

        $this->assertEquals("", json_decode($payload)->sub);

        $this->assertEquals($dateTime, json_decode($payload)->exp);

        $this->assertEquals("", json_decode($payload)->aud);
    }

    public function testGetMultiPayload()
    {
        $dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

        $builder = new TokenBuilder();

        $payload = $builder->setIssuer('http://127.0.0.1')
            ->setExpiration($dateTime)
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->addPayload(['key' => 'username', 'value' => 'rob1'])
            ->addPayload(['key' => 'description', 'value' => 'A great guy']);

        $payload = $payload->getPayload();

        $this->assertEquals('rob1', json_decode($payload)->username);

        $this->assertEquals('A great guy', json_decode($payload)->description);
    }

    public function testBuild()
    {
        $dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

        $builder = new TokenBuilder();

        $token = $builder->setIssuer('http://127.0.0.1')
            ->setExpiration($dateTime)
            ->setSecret('123ABC!kjhiop')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->build();

        $this->assertNotEmpty($token);

        $this->assertStringMatchesFormat('%s.%s.%s', $token);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Token cannot be built please add a payload, including an issuer and an expiration.
     */
    public function testBuildFail()
    {
        $builder = new TokenBuilder();

        $builder->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Token cannot be built please add a payload, including an issuer and an expiration.
     */
    public function testBuildFailIssuer()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString())
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Token secret not set, please add a secret to increase security
     */
    public function testBuildFailureSecret()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString())
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Token expiration date has already expired, please set a future expiration date
     */
    public function testBuildFailureExpirationOld()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration(Carbon::now()->subMinutes(2)->toDateTimeString())
            ->setSecret('&123ABCuytHj7')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     * @expectedExceptionMessageRegExp |^The date time string \[.*\] you attempted to parse is invalid\.$|
     */
    public function testBuildFailureExpirationInvalid()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration('Hello World')
            ->setSecret('!%123ABC!&jkfds')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     * @expectedExceptionMessageRegExp |^The date time string \[.*\] you attempted to parse is empty\.$|
     */
    public function testBuildFailureExpirationEmpty()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration('')
            ->setSecret('123!!&&ABCasJU90oj')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Failed to add payload, format wrong. Array must contain key and value.
     */
    public function testBadPayload()
    {
        $builder = new TokenBuilder();

        $builder->addPayload(['car' => 'user_id', 'value' => 2]);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Failed to add payload, format wrong. Array must contain key and value.
     */
    public function testBadPayloadOne()
    {
        $builder = new TokenBuilder();

        $builder->addPayload(['key' => 'user_id', 'park' => 2]);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     * @expectedExceptionMessage Failed to add payload, format wrong. Array must contain key and value.
     */
    public function testBadPayloadTwo()
    {
        $builder = new TokenBuilder();

        $builder->addPayload(['car' => 'user_id', 'park' => 2]);
    }

    public function testSetSubject()
    {
        $builder = new TokenBuilder();

        $builder->setSubject('Cars');

        $this->assertEquals('Cars', $builder->getSubject());
    }

    public function testGetNoSubject()
    {
        $builder = new TokenBuilder();

        $this->assertEquals('', $builder->getSubject());
    }

    public function testSetAudience()
    {
        $builder = new TokenBuilder();

        $builder->setAudience('People');

        $this->assertEquals('People', $builder->getAudience());
    }

    public function testGetNoAudience()
    {
        $builder = new TokenBuilder();

        $this->assertEquals('', $builder->getAudience());
    }


    public function testAddDuplicatePayloadKey()
    {
        $builder = new TokenBuilder();

        $builder->setIssuer('127.0.0.1')
            ->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString())
            ->addPayload(['key' => 'id', 'value' => 'hello'])
            ->addPayload(['key' => 'id', 'value' => 'world']);

        $this->assertEquals('world', json_decode($builder->getPayload())->id);
    }

    public function testCreateMultipleTokens()
    {
        $builder = new TokenBuilder();

        $jwt1 = $builder->setIssuer('127.0.0.1')
            ->setSecret('123ABC*$def456')
            ->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString())
            ->addPayload(['key' => 'id', 'value' => 'hello'])
            ->build();

        $jwt2 = $builder->setIssuer('127.0.0.1')
            ->setSecret('123ABC*$def456')
            ->setExpiration(Carbon::now()->addMinutes(20)->toDateTimeString())
            ->addPayload(['key' => 'id', 'value' => 'hello'])
            ->build();

        $this->assertNotEquals($jwt1, $jwt2);
    }

    public function testCreateMultipleTokensCheckPayloads()
    {
        $builder = new TokenBuilder();

        $time1 = Carbon::now()->addMinutes(10)->toDateTimeString();
        $time2 = Carbon::now()->addMinutes(19)->toDateTimeString();

        $jwt1 = $builder->setIssuer('127.0.0.1')
            ->setSecret('123ABC*$def456')
            ->setExpiration($time1)
            ->addPayload(['key' => 'id', 'value' => 'hello'])
            ->build();

        $jwt2 = $builder->setIssuer('localhost')
            ->setSecret('123ABC*$def456')
            ->setExpiration($time2)
            ->addPayload(['key' => 'id', 'value' => 'world'])
            ->build();

        $this->assertNotEquals($jwt1, $jwt2);

        $payload1 = json_decode(Token::getPayload($jwt1));
        $payload2 = json_decode(Token::getPayload($jwt2));

        $this->assertNotEquals($payload1->id, $payload2->id);
        $this->assertNotEquals($payload1->exp, $payload2->exp);

        $this->assertEquals($payload1->id, 'hello');
        $this->assertEquals($payload2->id, 'world');
    }
}
