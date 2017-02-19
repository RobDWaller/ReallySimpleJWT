<?php
 
use ReallySimpleJWT\TokenBuilder;
use Carbon\Carbon; 

class TokenBuilderTest extends PHPUnit_Framework_TestCase {

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
			->addPayload('user_id', 2);

		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $payload);

		$payload = $payload->getPayload();

		$this->assertNotEmpty($payload);

		$this->assertEquals(2, json_decode($payload)->user_id);

		$this->assertEquals("http://127.0.0.1", json_decode($payload)->iss);

		$this->assertEquals("", json_decode($payload)->sub);

		$this->assertEquals($dateTime, json_decode($payload)->exp);

		$this->assertEquals("", json_decode($payload)->aud);
	}

	public function testBuild()
	{
		$dateTime = Carbon::now()->addMinutes(10)->toDateTimeString();

		$builder = new TokenBuilder();

		$token = $builder->setIssuer('http://127.0.0.1')
			->setExpiration($dateTime)
			->setSecret('123ABC')
			->addPayload('user_id', 2)
			->build();

		$this->assertNotEmpty($token);

		$this->assertStringMatchesFormat('%s.%s.%s', $token);
	}
}