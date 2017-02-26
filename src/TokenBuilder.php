<?php namespace ReallySimpleJWT;

use ReallySimpleJWT\Exception\TokenBuilderException;
use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Helper\DateTime;
use Exception;

class TokenBuilder extends TokenAbstract
{
	private $type = 'JWT';

	private $secret;

	private $expiration;

	private $issuer;

	private $audience;

	private $subject;

	private $payload = [];

	private $signature;	

	public function getType()
	{
		return $this->type;
	}

	public function getSecret()
	{
		if (!empty($this->secret)) {
			return $this->secret;
		}

		throw new TokenBuilderException(
			'Token secret not set, please add a secret to increase security'
		);
	}

	public function getExpiration()
	{
		if (!$this->hasOldExpiration()) {
			return $this->expiration;
		}
		
		throw new TokenBuilderException(
			'Token expiration date has already expired, please set a future expiration date'
		);
	}

	public function getIssuer()
	{
		return $this->issuer;
	}

	public function getAudience()
	{
		return $this->audience;
	}

	public function getSubject()
	{
		return $this->subject;
	}

	public function getHeader()
	{
		return json_encode(['alg' => $this->getAlgorithm(), 'typ' => $this->getType()]);
	}

	public function getPayload()
	{
		if (!array_key_exists('iss', $this->payload)) {
			$this->payload = array_merge($this->payload, ['iss' => $this->getIssuer()]);
			$this->payload = array_merge($this->payload, ['exp' => $this->getExpiration()->toDateTimeString()]);
			$this->payload = array_merge($this->payload, ['sub' => $this->getSubject()]);
			$this->payload = array_merge($this->payload, ['aud' => $this->getAudience()]);
		}

		return json_encode($this->payload);
	}

	public function getSignature()
	{
		return new Signature($this->getHeader(), $this->getPayload(), $this->getSecret(), $this->getHash());
	}

	public function setSecret($secret)
	{
		$this->secret = $secret;

		return $this;
	}

	public function setExpiration($expiration)
	{
		$this->expiration = DateTime::parse($expiration);

		return $this;
	}

	public function setIssuer($issuer)
	{
		$this->issuer = $issuer;

		return $this;
	}

	/**
	 * Add key value pair to payload array
	 *
	 * @return TokenBuilder
	 */
	public function addPayload($key, $value)
	{
		$this->payload = array_merge($this->payload, [$key => $value]);

		return $this;
	}

	/**
	 * Check for payload, if it exists encode and return payload
	 *
	 * @return string
	 */
	private function encodePayload()
	{
		if (!empty($this->issuer) && !empty($this->expiration)) {
			return Base64::encode($this->getPayload());
		}

		throw new TokenBuilderException(
			'Token cannot be built please add a payload, including an issuer and an expiration.'
		);
	}

	/**
	 * Build and return the JSON Web Token
	 *
	 * @return string
	 */
	public function build()
	{
		return Base64::encode($this->getHeader()) . "." . 
			$this->encodePayload() . "." .
			$this->getSignature()->get();
	}

	private function hasOldExpiration()
	{
		return DateTime::olderThan(DateTime::now(), DateTime::parse($this->expiration));
	}
}