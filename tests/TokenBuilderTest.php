<?php
 
use ReallySimpleJWT\TokenBuilder;
 
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

	public function testGetPayload()
	{
		$builder = new TokenBuilder();

		$this->assertNotEmpty($builder->getPayload());		
	}

	public function testGetSignature()
	{
		$builder = new TokenBuilder();

		$this->assertNotEmpty($builder->getSignature());		
	}
   
	public function testSetSecret()
	{
		$builder = new TokenBuilder();

		$secret = $builder->setSecret('123');

		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $secret);

		$this->assertNotEmpty($secret->getSecret());
	}

	public function testSetExpiration()
	{
		$builder = new TokenBuilder();

		$expiration = $builder->setExpiration();

		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $expiration);

		$this->assertInstanceOf('Carbon\Carbon', $expiration->getExpiration());
	}

	public function testSetPayload()
	{
		$builder = new TokenBuilder();

		$payload = $builder->setPayload(2);

		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', $payload);

		$this->assertNotEmpty($payload->getPayload());
	}

	public function testBuild()
	{
		$builder = new TokenBuilder();

		$token = $builder->build();

		$this->assertNotEmpty($token);

		$this->assertStringMatchesFormat('%x.%x.%x', $token);
	}
}