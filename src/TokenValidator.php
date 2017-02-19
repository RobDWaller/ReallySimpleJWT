<?php namespace ReallySimpleJWT;

use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Exception\TokenValidatorException;
use Carbon\Carbon;

class TokenValidator extends TokenAbstract
{
	private $header;

	private $payload;

	private $signature;

	public function splitToken($tokenString)
	{
		$tokenParts = explode('.', $tokenString);

		if (count($tokenParts) === 3) {
			$this->header = $tokenParts[0];
			$this->payload = $tokenParts[1];
			$this->signature = $tokenParts[2];

			return $this;	
		}

		throw new TokenValidatorException(
			'Token string has invalid structure, ensure three strings seperated by dots.'
		);                                         
	}

	public function validateExpiration()
	{
		$now = Carbon::now();

		$expiration = Carbon::parse($this->getExpiration());

		if ($now->diffInSeconds($expiration, false) < 0) {
			throw new TokenValidatorException('This token has expired!');
		}

		return $this;
	}

	public function validateSignature($secret)
	{
		$signature = new Signature($this->getHeader(), $this->getPayload(), $secret, $this->getHash());

		if ($signature->get() === $this->signature) {
			return true;
		} 

		throw new TokenValidatorException(
			'Token signature is invalid!! Input: ' . $this->signature . ' !== Generated: ' . $signature->get()
		);	
	}

	public function getExpiration()
	{
		return json_decode($this->getPayload())->exp;
	}

	public function getPayload()
	{
		return Base64::decode($this->payload);
	}

	public function getHeader()
	{
		return Base64::decode($this->header);
	}
}