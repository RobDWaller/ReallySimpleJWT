<?php namespace ReallySimpleJWT;

class TokenBuilder
{
	private $hash = 'HS256';

	private $type = 'JWT';

	private $secret;

	private $expiration;

	private $payload;

	private $signature;

	public function getHash()
	{
		return $this->hash;
	}	

	public function getType()
	{
		return $this->type;
	}

	public function getSecret()
	{
		return $this->secret;
	}

	public function getHeader()
	{
		return json_encode(['alg' => $this->getHash(), 'typ' => $this->getType()]);
	}

	public function getPayload()
	{
		return $this->payload;
	}

	public function getSignature()
	{
		return $this->signature;
	}

	public function setSecret($secret)
	{
		$this->secret = $secret;

		return $this;
	}

	public function setExpiration($dateTimeString)
	{
		$this->expiration = $expiration;

		return $this;
	}

	public function setPayload($userId)
	{
		$this->payload = $userId;

		return $this;
	}

	public function build()
	{

	}
}