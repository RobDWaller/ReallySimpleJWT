<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

class Encode
{
    private const ALGORITHM = 'HS256';

    private const HASH = 'sha256';

    public function encode(string $toEncode): string
    {
        return $this->toBase64Url(base64_encode($toEncode));
    }

    private function toBase64Url(string $base64): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }

    public function signature(string $header, string $payload, string $secret): string
    {
        return $this->encode(
            $this->hash(
                self::HASH,
                $this->encode($header) . "." . $this->encode($payload),
                $secret
            )
        );
    }

    /**
     * Why do I return this as raw binary?
     */
    public function hash(string $algorithm, string $toHash, string $secret): string
    {
        return hash_hmac($algorithm, $toHash, $secret, true);
    }

    public function getAlgorithm()
    {
        return self::ALGORITHM;
    }

    public function getHash()
    {
        return self::HASH;
    }

    public function decode(string $toDecode): string
    {
        return (string) base64_decode(
            $this->addPadding($this->toBase64($toDecode)),
            true
        );
    }

    private function toBase64(string $urlString): string
    {
        return str_replace(['-', '_'], ['+', '/'], $urlString);
    }

    private function addPadding(string $urlString): string
    {
        if (strlen($urlString) % 4 !== 0) {
            return $this->addPadding($urlString . '=');
        }

        return $urlString;
    }
}
