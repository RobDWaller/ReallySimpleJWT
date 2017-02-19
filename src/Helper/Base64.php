<?php namespace ReallySimpleJWT\Helper;

class Base64
{
	public static function encode($string)
	{
		return base64_encode($string);
	}

	public static function decode($string)
	{
		return base64_decode($string);
	}
}