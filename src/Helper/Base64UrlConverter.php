<?php namespace ReallySimpleJWT\Helper;

class Base64UrlConverter
{
	private $base64String;

	private $base64UrlString;

	public function setBase64String($base64String)
	{
		$this->base64String = $base64String;

		return $this;
	}

	public function setBase64UrlString($base64UrlString)
	{
		$this->base64UrlString = $base64UrlString;

		return $this;
	}

	private function replacePlus()
	{
		$this->base64UrlString = str_replace('+', '-', $this->base64String);

		return $this;
	}

	private function replaceSlash()
	{
		$this->base64UrlString = str_replace('/', '_', $this->base64UrlString);

		return $this;
	}

	private function removePadding()
	{
		$this->base64UrlString = str_replace('=', '', $this->base64UrlString);

		return $this;
	}

	private function replaceDash()
	{
		$this->base64String = str_replace('-', '+', $this->base64UrlString);

		return $this;
	}

	private function replaceUnderscore()
	{
		$this->base64String = str_replace('_', '/', $this->base64String);

		return $this;
	}

	public function toBase64Url()
	{
		$this->replacePlus()
			->replaceSlash()
			->removePadding();

		return $this;
	}

	public function toBase64()
	{
		$this->replaceDash()
			->replaceUnderscore();

		return $this;
	}

	public function getBase64String()
	{
		return $this->base64String;
	}

	public function getBase64UrlString()
	{
		return $this->base64UrlString;
	}
}