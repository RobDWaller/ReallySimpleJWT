<?php namespace ReallySimpleJWT;

abstract class TokenAbstract 
{
	private $hash = 'sha256';

	private $algorithm = 'HS256';

	public function getHash()
	{
		return $this->hash;
	}

	public function getAlgorithm()
	{
		return $this->algorithm;
	}
}