<?php

namespace SuperSafeSecuritySystemsAuthentication\Exceptions;

use Throwable;

class UserCreationException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct('You need to provide an e-mail, password and display name to create an account.', $code, $previous);
    }
}
