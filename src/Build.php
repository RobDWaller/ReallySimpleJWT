<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Interfaces\Encoder;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Helper\JsonEncoder;
use ReallySimpleJWT\Interfaces\Secret;
use ReallySimpleJWT\Exception\ValidateException;

/**
 * A class to build a JSON Web Token, returns the token as an instance of
 * ReallySimpleJWT\Jwt.
 *
 * Class contains helper methods that allow you to easily set JWT claims
 * defined in the JWT RFC. Eg setIssuer() will set the iss claim in the
 * JWT payload.
 *
 * For more information on JSON Web Tokens please refer to the RFC. This
 * library attempts to comply with the JWT RFC as closely as possible.
 * https://tools.ietf.org/html/rfc7519
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
class Build
{
    use JsonEncoder;

    /**
     * Defines the type of JWT to be created, usually just JWT.
     *
     * @var string
     */
    private $type;

    /**
     * Holds the JWT header claims
     *
     * @var array
     */
    private $header = [];

    /**
     * Holds the JWT payload claims.
     *
     * @var array
     */
    private $payload = [];

    /**
     * The secret string for encoding the JWT signature.
     *
     * @var string
     */
    private $secret;

    /**
     * A class of validation helper methods.
     *
     * @var Validate
     */
    private $validate;

    /**
     * Validate token signature secret.
     */
    private $secretValidator;

    /**
     * A class to encode JWT tokens.
     *
     * @var Interfaces\Encoder
     */
    private $encode;

    /**
     * Build class constructor.
     *
     * @param string $type
     * @param Validate $validate
     * @param Interfaces\Encoder $encode
     */
    public function __construct(string $type, Validate $validate, Secret $secretValidator, Encoder $encode)
    {
        $this->type = $type;

        $this->validate = $validate;

        $this->secretValidator =  $secretValidator;

        $this->encode = $encode;
    }

    /**
     * Define the content type header claim for the JWT. This defines
     * structural information about the token. For instance if it is a
     * nested token.
     *
     * @param string $contentType
     * @return Build
     */
    public function setContentType(string $contentType): self
    {
        $this->header['cty'] = $contentType;

        return $this;
    }

    /**
     * Add custom claims to the JWT header
     *
     * @param string $key
     * @param mixed $value
     * @return Build
     */
    public function setHeaderClaim(string $key, $value): self
    {
        $this->header[$key] = $value;

        return $this;
    }

    /**
     * Get the contents of the JWT header. This is an associative array of
     * the defined header claims. The JWT algorithm and typ are added
     * by default.
     *
     * @return array
     */
    public function getHeader(): array
    {
        return array_merge(
            $this->header,
            ['alg' => $this->encode->getAlgorithm(), 'typ' => $this->type]
        );
    }

    /**
     * Set the JWT secret for encrypting the JWT signature. The secret must
     * comply with the validation rules defined in the
     * ReallySimpleJWT\Validate class.
     *
     * @param string $secret
     * @return Build
     * @throws Exception\ValidateException
     */
    public function setSecret(string $secret): self
    {
        if (!$this->secretValidator->validate($secret)) {
            throw new ValidateException('Invalid secret.', 9);
        }

        $this->secret = $secret;

        return $this;
    }

    /**
     * Set the issuer JWT payload claim. This defines who issued the token.
     * Can be a string or URI.
     *
     * @param string $issuer
     * @return Build
     */
    public function setIssuer(string $issuer): self
    {
        $this->payload['iss'] = $issuer;

        return $this;
    }

    /**
     * Set the subject JWT payload claim. This defines who the JWT is for.
     * Eg an application user or admin.
     *
     * @param string $subject
     * @return Build
     */
    public function setSubject(string $subject): self
    {
        $this->payload['sub'] = $subject;

        return $this;
    }

    /**
     * Set the audience JWT payload claim. This defines a list of 'principals'
     * who will process the JWT. Eg a website or websites who will validate
     * users who use this token. This claim can either be a single string or an
     * array of strings.
     *
     * @param mixed $audience
     * @return Build
     * @throws Exception\ValidateException
     */
    public function setAudience($audience): self
    {
        if (is_string($audience) || is_array($audience)) {
            $this->payload['aud'] = $audience;

            return $this;
        }

        throw new ValidateException('Invalid Audience claim.', 10);
    }

    /**
     * Set the expiration JWT payload claim. This sets the time at which the
     * JWT should expire and no longer be accepted.
     *
     * @param int $timestamp
     * @return Build
     * @throws Exception\ValidateException
     */
    public function setExpiration(int $timestamp): self
    {
        if (!$this->validate->expiration($timestamp)) {
            throw new ValidateException('Expiration claim has expired.', 4);
        }

        $this->payload['exp'] = $timestamp;

        return $this;
    }

    /**
     * Set the not before JWT payload claim. This sets the time after which the
     * JWT can be accepted.
     *
     * @param int $notBefore
     * @return Build
     */
    public function setNotBefore(int $notBefore): self
    {
        $this->payload['nbf'] = $notBefore;

        return $this;
    }

    /**
     * Set the issued at JWT payload claim. This sets the time at which the
     * JWT was issued / created.
     *
     * @param int $issuedAt
     * @return Build
     */
    public function setIssuedAt(int $issuedAt): self
    {
        $this->payload['iat'] = $issuedAt;

        return $this;
    }

    /**
     * Set the JSON token identifier JWT payload claim. This defines a unique
     * identifier for the token.
     *
     * @param string $jwtId
     * @return Build
     */
    public function setJwtId(string $jwtId): self
    {
        $this->payload['jti'] = $jwtId;

        return $this;
    }

    /**
     * Set a custom payload claim on the JWT. The RFC calls these private
     * claims. Eg you may wish to set a user_id or a username in the
     * JWT payload.
     *
     * @param string $key
     * @param mixed $value
     * @return Build
     */
    public function setPayloadClaim(string $key, $value): self
    {
        $this->payload[$key] = $value;

        return $this;
    }

    /**
     * Get the JWT payload. This will return an array of registered claims and
     * private claims which make up the JWT payload.
     *
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Build the token, this is the last method which should be called after
     * all the header and payload claims have been set. It will encode the
     * header and payload, and generate the JWT signature. It will then
     * concatenate each part with dots into a single string.
     *
     * This JWT string along with the secret are then used to generate a new
     * instance of the JWT class which is returned.
     *
     * @return Jwt
     */
    public function build(): Jwt
    {
        return new Jwt(
            $this->encode->encode($this->jsonEncode($this->getHeader())) . "." .
            $this->encode->encode($this->jsonEncode($this->getPayload())) . "." .
            $this->getSignature(),
            $this->secret
        );
    }

    /**
     * If you wish to use the same build instance to generate two or more
     * tokens you can use this reset method to unset the pre-defined header,
     * payload and secret properties.
     *
     *  @return Build
     */
    public function reset(): self
    {
        $this->payload = [];
        $this->header = [];
        $this->secret = '';

        return $this;
    }

    /**
     * Generate and return the JWT signature this is made up of the header,
     * payload and secret.
     *
     * @return string
     * @throws Exception\ValidateException
     */
    private function getSignature(): string
    {
        if (!empty($this->secret)) {
            return $this->encode->signature(
                $this->jsonEncode($this->getHeader()),
                $this->jsonEncode($this->getPayload()),
                $this->secret
            );
        }

        throw new ValidateException('Invalid secret.', 9);
    }
}
