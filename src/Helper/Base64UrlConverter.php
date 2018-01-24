<?php namespace ReallySimpleJWT\Helper;

/**
 * A class that converts Base64 strings to Base64Url strings and vice versa
 * for JWT Tokens
 *
 * @author Rob Waller <rdwaller1984@gmail.com>
 */
class Base64UrlConverter
{
    /**
     * The base64 string
     *
     * @var string
     */
    private $base64String;

    /**
     * The base64 Url string
     *
     * @var string
     */
    private $base64UrlString;

    /**
     * Set the base64 string first step in
     *
     * @param string $base64String
     *
     * @return self
     */
    public function setBase64String(string $base64String): self
    {
        $this->base64String = $base64String;

        return $this;
    }

    /**
     * Set the base64 Url string
     *
     * @param string $base64UrlString
     *
     * @return self
     */
    public function setBase64UrlString(string $base64UrlString): self
    {
        $this->base64UrlString = $base64UrlString;

        return $this;
    }

    /**
     * Convert a base64 string to a base64 url string by replacing defined characters
     *
     * @return self
     */
    private function convertToBase64Url(): self
    {
        $this->base64UrlString = str_replace(['+', '/', '='], ['-', '_', ''], $this->base64String);

        return $this;
    }

    /**
     * Add base64 padding to converted base64 Url string if it is required, basically
     * if the outputted base64 string is too short.
     *
     * @param string $unpaddedString
     *
     * @return string
     */
    private function addBase64Padding(string $unpaddedString): string
    {
        if (strlen($unpaddedString) % 4 !== 0) {
            return $this->addBase64Padding($unpaddedString . '=');
        }

        return $unpaddedString;
    }

    /**
     * Convert base64 Url string to base64 string
     *
     * @return self
     */
    private function convertToBase64(): self
    {
        $this->base64String = $this->addBase64Padding(
            str_replace(['-', '_'], ['+', '/'], $this->base64UrlString)
        );

        return $this;
    }

    /**
     * Trigger base64 string to base64 Url string process
     *
     * @return self
     */
    public function toBase64Url(): self
    {
        $this->convertToBase64Url();

        return $this;
    }

    /**
     * Trigger base64 Url string to base64 string process
     *
     * @return self
     */
    public function toBase64(): self
    {
        $this->convertToBase64();

        return $this;
    }

    /**
     * Get base64 string
     *
     * @return string
     */
    public function getBase64String(): string
    {
        return $this->base64String;
    }

    /**
     * Get base64 Url string
     *
     * @return string
     */
    public function getBase64UrlString(): string
    {
        return $this->base64UrlString;
    }
}
