<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Encoders;

use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Helper\JsonEncoder;
use ReallySimpleJWT\Helper\Base64;

/**
 * HS256 / sha256 implementation of the Encode interface.
 *
 * Core ReallySimpleJWT token encoder class for encoding JWT parts
 * and signatures.
 */
class EncodeHS256 implements Encode
{
    use JsonEncoder;
    use Base64;

    /**
     * The Algorithm which was used to hash the token signature. This is what
     * is displayed as the alg claim in the token header. Note this may be
     * slightly different from the actual algorithm used to hash the
     * signature string.
     */
    private const ALGORITHM = 'HS256';

    /**
     * This is the actual algorithm used to hash the token's signature string.
     */
    private const HASH_ALGORITHM = 'sha256';

    /**
     * The secret string required to secure the token signature.
     */
    private string $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * Get the algorithm used to encode the signature. Note this is for show,
     * it is what is displayed in the JWT header as the alg claim.
     */
    public function getAlgorithm(): string
    {
        return self::ALGORITHM;
    }

    /**
     * Get the hash algorithm string to be used when encoding the signature,
     * this is the actual hash type used to encode the signature.
     */
    private function getHashAlgorithm(): string
    {
        return self::HASH_ALGORITHM;
    }

    /**
     * Encode a JSON string to a Base64Url string.
     */
    private function urlEncode(string $toEncode): string
    {
        return $this->toBase64Url(base64_encode($toEncode));
    }

    /**
     * Encode a json string in Base64 Url format.
     *
     * @param mixed[] $toEncode
     */
    public function encode(array $toEncode): string
    {
        return $this->urlEncode($this->jsonEncode($toEncode));
    }

    /**
     * Generate the JWT signature. The header and payload are encoded,
     * concatenated with a dot, hashed via sha256 with a secret, and then
     * encoded and returned.
     *
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function signature(array $header, array $payload): string
    {
        return $this->urlEncode(
            $this->hash(
                $this->getHashAlgorithm(),
                $this->encode($header) . "." . $this->encode($payload),
                $this->secret
            )
        );
    }

    /**
     * Hash the JWT signature string using sha256.
     */
    private function hash(string $algorithm, string $toHash, string $secret): string
    {
        return hash_hmac($algorithm, $toHash, $secret, true);
    }
}
