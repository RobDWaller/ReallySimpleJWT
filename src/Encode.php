<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

/**
 * Class used to encode the JSON Web Token signature. Also defines the
 * hash / algorithm to be used.
 *
 * This class is written so it is replaceable with a custom encoding.
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 * @todo this class needs some tidyup addPadding method is semantically wrong
 * and the hash algorithm stuff needs clarifying. Also need to add
 * the interface.
 */
class Encode
{
    private const ALGORITHM = 'HS256';

    private const HASH = 'sha256';

    /**
     * Get the algorithm used to encode the signature. Note this is for show,
     * it is what is displayed in the JWT header as the alg claim.
     *
     * @return string
     */
    public function getAlgorithm()
    {
        return self::ALGORITHM;
    }

    /**
     * Get the hash to be used when encoding the signature, nte this is the
     * actual hash type used to encode the signature.
     *
     * @return string
     */
    public function getHash()
    {
        return self::HASH;
    }

    /**
     * Encode a json string in Base64 Url format.
     *
     * @param string $toEncode
     * @return string
     */
    public function encode(string $toEncode): string
    {
        return $this->toBase64Url(base64_encode($toEncode));
    }

    /**
     * Decode a Base64 Url string to a json string
     *
     * @param string $toDecode
     * @return string
     */
    public function decode(string $toDecode): string
    {
        return (string) base64_decode(
            $this->addPadding($this->toBase64($toDecode)),
            true
        );
    }

    /**
     * Generate the JWT signature. The header and payload are encoded,
     * concatenated with a dot, hashed via sha256 with a secret, and then
     * encoded and returned.
     *
     * @param string $header
     * @param string $payload
     * @param string $secret
     * @return string
     */
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
     * Hash the JWT signature string using sha256.
     *
     * @param string $algorithm
     * @param string $toHash
     * @param string $secret
     * @return string
     */
    public function hash(string $algorithm, string $toHash, string $secret): string
    {
        return hash_hmac($algorithm, $toHash, $secret, true);
    }

    /**
     * Convert a base64 string to a base64 Url string
     *
     * @param string $base64
     * @return string
     */
    private function toBase64Url(string $base64): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }

    /**
     * Convert a base64 URL string to a base64 string
     *
     * @param string $urlString
     * @return string
     */
    private function toBase64(string $urlString): string
    {
        return str_replace(['-', '_'], ['+', '/'], $urlString);
    }

    /**
     * Add padding to base64 string which require it. Some base64 URL strings
     * which are decode will have missing padding which is represented by the
     * equals sign.
     *
     * @param string $urlString
     * @return string
     */
    private function addPadding(string $urlString): string
    {
        if (strlen($urlString) % 4 !== 0) {
            return $this->addPadding($urlString . '=');
        }

        return $urlString;
    }
}
