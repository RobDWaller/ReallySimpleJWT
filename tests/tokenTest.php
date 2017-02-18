<?php
 
use ReallySimpleJWT\Token;
 
class TokenTest extends PHPUnit_Framework_TestCase {
 
  	public function testGetToken()
	{
    	$this->assertNotEmpty(Token::getToken());
  	}

  	public function testValidateToken()
  	{
  		$token = Token::getToken();

  		$this->assertTrue(Token::validate($token));
  	}
 
}