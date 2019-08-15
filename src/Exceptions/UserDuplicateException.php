<?php

namespace SuperSafeSecuritySystemsAuthentication\Exceptions;

use Throwable;

class UserDuplicateException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct('A user is already signed up with this e-mail address.', $code, $previous);
    }
}
