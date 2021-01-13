<?php

namespace Tests\Fixtures;

class Tokens
{
    public const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbmRyYSB' .
        'UaG9tcHNvbiIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNT' .
        'E2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMDAsImF1ZCI6Im15c2l0ZS5jb20ifQ.' .
        'x50kuh6RBKnWmSh2lpTpEZ48ttZgbXdsLPI269tRRXc';

    public const HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

    public const PAYLOAD = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbmRyYSBUaG9tcHNv' .
        'biIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkw' .
        'MDAsImF1ZCI6Im15c2l0ZS5jb20ifQ';

    public const SIGNATURE = 'x50kuh6RBKnWmSh2lpTpEZ48ttZgbXdsLPI269tRRXc';

    public const SECRET = 'hello123';

    public const DECODED_HEADER = ["alg" => "HS256", "typ" => "JWT"];

    public const DECODED_PAYLOAD = [
        "sub" => "1234567890",
        "name" => "Sandra Thompson",
        "iat" => 1516239022,
        "exp" => 1516239022,
        "nbf" => 1516239000,
        "aud" => "mysite.com"
    ];

    public const ALGORITHM = 'HS256';

    /**
     * For tests with tokens with no nbf or exp claim.
     */
    public const TOKEN_NO_TIMES = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'z8KOZagJYYZ5CfTPFUEn59ksYpm8Fo2kldmZqwwoAic';
}
