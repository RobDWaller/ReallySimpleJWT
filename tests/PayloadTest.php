<?php
 
use ReallySimpleJWT\Helper\Payload;

class PayloadTest extends PHPUnit_Framework_TestCase 
{
	public function testPayload()
	{
		$payload = new Payload('Hello', 'World');

		$this->assertEquals($payload->getKey(), 'Hello');

		$this->assertEquals($payload->getValue(), 'World'); 
	}
}