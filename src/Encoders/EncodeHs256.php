<?php

namespace ReallySimpleJWT\Encoders;

use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Helper\JsonEncoder;
use ReallySimpleJWT\Helper\Base64;

class EncodeHs256 implements Encode
{
    use JsonEncoder, Base64;

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
     * Get the algorithm used to encode the signature. Note this is for show,
     * it is what is displayed in the JWT header as the alg claim.
     *
     * @return string
     */
    public function getAlgorithm(): string
    {
        return self::ALGORITHM;
    }

    /**
     * Get the hash algorithm string to be used when encoding the signature,
     * this is the actual hash type used to encode the signature.
     *
     * @return string
     */
    private function getHashAlgorithm(): string
    {
        return self::HASH_ALGORITHM;
    }

    private function urlEncode(string $toEncode): string
    {
        return $this->toBase64Url(base64_encode($toEncode));
    }

    /**
     * Encode a json string in Base64 Url format.
     *
     * @param string $toEncode
     * @return string
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
     * @param string $header
     * @param string $payload
     * @param string $secret
     * @return string
     */
    public function signature(array $header, array $payload, string $secret): string
    {
        return $this->urlEncode(
            $this->hash(
                $this->getHashAlgorithm(),
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
    private function hash(string $algorithm, string $toHash, string $secret): string
    {
        return hash_hmac($algorithm, $toHash, $secret, true);
    }
}