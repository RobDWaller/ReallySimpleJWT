<?php namespace ReallySimpleJWT;

use ReallySimpleJWT\Helper\Payload;

class Token
{
	public static function getToken($userId, $secret, $expiration, $issuer)
	{
		$builder = Self::builder();

		return $builder->addPayload(new Payload('user_id', $userId))
			->setSecret($secret)
			->setExpiration($expiration)
			->setIssuer($issuer)
			->build();
	}

	public static function validate($token)
	{

	}

	public static function builder()
	{
		return new TokenBuilder();
	}

	public static function validator()
	{
		return new TokenValidator();
	}
}