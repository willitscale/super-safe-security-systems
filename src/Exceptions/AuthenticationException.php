<?php

namespace SuperSafeSecuritySystemsAuthentication\Exceptions;

use Throwable;

class AuthenticationException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct('Invalid credentials have been passed', $code, $previous);
    }
}
