<?php
 
use ReallySimpleJWT\Token;
use Carbon\Carbon;
 
class TokenTest extends PHPUnit_Framework_TestCase {
 
  	public function testGetToken()
	{
		$token = Token::getToken(
            1,
            '123ABC', 
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            '127.0.0.1'
        );

        $this->assertNotEmpty($token);
  	}

  	public function testValidateToken()
  	{
  		$token = Token::getToken(
            'abdY',
            'Hello&Mike', 
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            'http://127.0.0.1'
        );

  		$this->assertTrue(Token::validate($token, 'Hello&Mike'));
  	}
	
	public function testBuilder()
	{
		$this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', Token::builder());
	} 

    public function testValidator()
    {
        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', Token::validator());  
    }
}