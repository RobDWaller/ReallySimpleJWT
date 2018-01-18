<?php

use ReallySimpleJWT\TokenBuilder;
use Carbon\Carbon;
use PHPUnit\Framework\TestCase;

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

        $secret = $builder->setSecret('123');

        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $secret);

        $this->assertEquals('123', $secret->getSecret());
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
            ->setSecret('123ABC')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->build();

        $this->assertNotEmpty($token);

        $this->assertStringMatchesFormat('%s.%s.%s', $token);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     */
    public function testBuildFail()
    {
        $builder = new TokenBuilder();

        $builder->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
     */
    public function testBuildFailIssuer()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration(Carbon::now()->addMinutes(10)->toDateTimeString())
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenBuilderException
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
     */
    public function testBuildFailureExpirationOld()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration(Carbon::now()->subMinutes(2)->toDateTimeString())
            ->setSecret('123ABC')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     */
    public function testBuildFailureExpirationInvalid()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration('Hello World')
            ->setSecret('123ABC')
            ->addPayload(['key' => 'user_id', 'value' => 2])
            ->setIssuer('127.0.0.1')
            ->build();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenDateException
     */
    public function testBuildFailureExpirationEmpty()
    {
        $builder = new TokenBuilder();

        $builder->setExpiration('')
            ->setSecret('123ABC')
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
}
