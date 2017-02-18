<?php
 
use ReallySimpleJWT\Helper\Signature;

class SignatureTest extends PHPUnit_Framework_TestCase 
{
	public function testSignature()
	{
		$signature = new Signature('header', 'payload', '123', 'sha256');

		$signature = $signature->get();

		$this->assertNotEmpty($signature);

		$this->assertEquals(
			base64_encode(hash_hmac('sha256', base64_encode('header') . "." . base64_encode('payload'), '123', true)), 
			$signature
		);
	}
}