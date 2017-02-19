<?php namespace ReallySimpleJWT\Helper;

class Hmac
{
	public static function hash($hash, $string, $secret, $output = true)
	{
		return hash_hmac($hash, $string, $secret, $output);
	}
}