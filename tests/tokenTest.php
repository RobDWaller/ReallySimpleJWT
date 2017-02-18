<?php
 
use ReallySimpleJWT\Token;
 
class TokenTest extends PHPUnit_Framework_TestCase {
 
  	public function testGetToken()
	{
		$token = Token::getToken(1);

    	$this->assertNotEmpty($token);

    	$this->assertStringMatchesFormat('%x.%x.%x', $token);
  	}

  	public function testValidateToken()
  	{
  		$token = Token::getToken(1);

  		$this->assertTrue(Token::validate($token));
  	}
	
	public function testMake()
	{
		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', Token::make());
	} 
}