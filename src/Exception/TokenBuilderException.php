<?php namespace ReallySimpleJWT\Exception;

use Exception;

class TokenBuilderException extends Exception
{
	public function __construct($message, $code = 0, $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}