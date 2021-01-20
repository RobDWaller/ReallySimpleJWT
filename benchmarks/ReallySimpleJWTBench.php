<?php

namespace Benchmarks;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Decode;
use ReallySimpleJWT\Helper\Validator;

class ReallySimpleJWTBench
{
    /**
     * @Revs(2500)
     * @Iterations(20)
     */
    public function benchCreateToken(): void
    {
        $build = new Build(
            'JWT',
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();
    }

    /**
     * @Revs(2500)
     * @Iterations(20)
     */
    public function benchParseToken(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.' .
        'dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio';

        $parse = new Parse(new Jwt($token, '123$car*PARK456'), new Decode());

        $parse->parse();
    }

    /**
     * @Revs(1250)
     * @Iterations(10)
     */
    public function benchBuildAndParse(): void
    {
        $build = new Build(
            'JWT',
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new Decode());

        $parse->parse();
    }
}
