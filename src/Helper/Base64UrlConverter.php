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

    private function convertToBase64Url()
    {
        $this->base64UrlString = str_replace(['+', '/', '='], ['-', '_', ''], $this->base64String);

        return $this;
    }

    private function addBase64Padding($unpaddedString)
    {
        if (strlen($unpaddedString) % 4 !== 0) {
            return $this->addBase64Padding($unpaddedString . '=');
        }

        return $unpaddedString;
    }

    private function convertToBase64()
    {
        $this->base64String = $this->addBase64Padding(
            str_replace(['-', '_'], ['+', '/'], $this->base64UrlString)
        );

        return $this;
    }

    public function toBase64Url()
    {
        $this->convertToBase64Url();

        return $this;
    }

    public function toBase64()
    {
        $this->convertToBase64();

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
