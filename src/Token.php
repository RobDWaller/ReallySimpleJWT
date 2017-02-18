<?php namespace ReallySimpleJWT;

class Token
{
	public static function getToken($userId, $secret, $expiration, $issuer)
	{

	}

	public static function validate($token)
	{

	}

	public static function make()
	{
		return new TokenBuilder();
	}
}