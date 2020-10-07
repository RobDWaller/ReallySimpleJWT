<?php

namespace Tests\Fixtures;

class Tokens {

    const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbmRyYSBUaG9tcHNvbiIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMDAsImF1ZCI6Im15c2l0ZS5jb20ifQ.' .
        'x50kuh6RBKnWmSh2lpTpEZ48ttZgbXdsLPI269tRRXc';

    const HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

    const PAYLOAD = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbmRyYSBUaG9tcHNvbiIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJuYmYiOjE1MTYyMzkwMDAsImF1ZCI6Im15c2l0ZS5jb20ifQ';

    const SIGNATURE = 'x50kuh6RBKnWmSh2lpTpEZ48ttZgbXdsLPI269tRRXc';

    const SECRET = 'hello123';

    const DECODED_HEADER = ["alg" => "HS256", "typ" => "JWT"];

    const DECODED_PAYLOAD = [
        "sub" => "1234567890", 
        "name" => "Sandra Thompson",
        "iat" => 1516239022, 
        "exp" => 1516239022,
        "nbf" => 1516239000,
        "aud" => "mysite.com"
    ];
}