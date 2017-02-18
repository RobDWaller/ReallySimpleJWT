<?php namespace ReallySimpleJWT\Helper;

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
		return hash_hmac(
			$this->hash,
			base64_encode($this->header) . "." . base64_encode($this->payload),
			$this->secret
		);
	}
}