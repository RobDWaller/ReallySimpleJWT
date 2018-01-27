<?php

namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Exception\SecretException;

/**
 * A simply class for validating secret key format
 *
 * A good secret is 12 characters or more, contains numbers, upper and lowercase
 * letters and some special characters *&!@%^#$.
 *
 * Example good secrect: HELLOworldFOOBAR123*&!@%^#$
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
class Secret
{
    /**
     * Validate a secret key string complies with the defined rules.
     *
     * @param string $secret
     * @return bool
     * @throws SecrectException
     */
    public static function validate(string $secret): bool
    {
        if (strlen($secret) < 12) {
            throw new SecretException('The secret you provided must be at least 12 characters in length.');
        }

        if (!preg_match('/[0-9]/', $secret)) {
            throw new SecretException('The secret you provided must contain number characters.');
        }

        if (!preg_match('/[A-Z]/', $secret)) {
            throw new SecretException('The secret you provided must contain uppercase letters.');
        }

        if (!preg_match('/[a-z]/', $secret)) {
            throw new SecretException('The secret you provided must contain lowercase letters.');
        }

        if (!preg_match('/[\*&!@%\^#\$]/', $secret)) {
            throw new SecretException('The secret you provided must contain some special characters (*&!@%^#$).');
        }

        return true;
    }
}
