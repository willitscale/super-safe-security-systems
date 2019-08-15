<?php

namespace SuperSafeSecuritySystemsAuthentication\Exceptions;

use Throwable;

class MaxAttemptsException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct('Maximum login attempts have been exceeded', $code, $previous);
    }
}
