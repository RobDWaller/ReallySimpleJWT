<?php namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Helper\Hmac;
use ReallySimpleJWT\Helper\Base64;

class Signature
{
	private $header;

	private $payload;	

	private $secret;

	private $hash;

	public function __construct($header, $payload, $secret, $hash)
	{
		$this->header = $header;

		$this->payload = $payload;

		$this->secret = $secret;

		$this->hash = $hash;
	}

	public function get()
	{
		return Base64::encode(Hmac::hash(
			$this->hash,
			$this->signatureString(),
			$this->secret
		));
	}

	private function signatureString()
	{
		return Base64::encode($this->header) . '.' . Base64::encode($this->payload);
	}
}