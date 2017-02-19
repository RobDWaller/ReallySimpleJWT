<?php
 
use ReallySimpleJWT\Token;
use ReallySimpleJWT\TokenValidator;
use Carbon\Carbon; 

class TokenValidatorTest extends PHPUnit_Framework_TestCase
{
	public function testValidateSuccessful()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			54, 
			'ab&7dj)9)', 
			Carbon::now()->addMinutes(11)->toDateTimeString(),
			'www.mysite.com'
		);

		$this->assertTrue(
			$validator->splitToken($tokenString)
				->validateExpiration()
				->validateSignature('ab&7dj)9)')
		);
	}

	public function testGetPayload()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			'twelve123', 
			'op(9odP', 
			Carbon::now()->addMinutes(5)->toDateTimeString(),
			'www.mysite.com'
		);

		$payload = $validator->splitToken($tokenString)
			->getPayload();

		$this->assertEquals('twelve123', json_decode($payload)->user_id);
	}

	public function testValidateExpiration()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			'twelve123', 
			'op(9odP', 
			Carbon::now()->addMinutes(2)->toDateTimeString(),
			'www.mysite.com'
		);

		$payload = $validator->splitToken($tokenString)
			->validateExpiration();

		$this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testValidateExpirationFailure()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			201923, 
			12386, 
			Carbon::now()->subMinutes(3)->toDateTimeString(),
			'www.yoursite.com'
		);

		$validator->splitToken($tokenString)
			->validateExpiration();
	}

}