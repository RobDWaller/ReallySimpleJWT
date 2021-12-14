<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

trait Base64
{
    /**
     * Convert a base64 string to a base64 Url string.
     */
    public function toBase64Url(string $base64): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }

    /**
     * Convert a base64 URL string to a base64 string.
     */
    public function toBase64(string $urlString): string
    {
        return str_replace(['-', '_'], ['+', '/'], $urlString);
    }

    /**
     * Add padding to base64 strings which require it. Some base64 URL strings
     * which are decoded will have missing padding which is represented by the
     * equals sign.
     */
    public function addPadding(string $base64String): string
    {
        if (strlen($base64String) % 4 !== 0) {
            return $this->addPadding($base64String . '=');
        }

        return $base64String;
    }
}
