<?php

namespace SuperSafeSecuritySystemsAuthentication;

use SuperSafeSecuritySystemsAuthentication\Exceptions\AuthenticationException;
use SuperSafeSecuritySystemsAuthentication\Exceptions\MaxAttemptsException;
use SuperSafeSecuritySystemsAuthentication\Exceptions\UserCreationException;

/**
 * Class Authentication
 * @package SuperSafeSecuritySystems
 */
class SuperSafeSecuritySystemsAuthentication
{
    const DATE_FORMAT = 'Y-m-d H:i:s';
    const MAX_ATTEMPTS = 5;
    const MAX_ATTEMPTS_DURATION_IN_SECONDS = 30;
    const DUPLICATE_USER_MYSQL_ERROR = 1062;
    const DEFAULT_LEVEL = 1;

    /**
     * @var \mysqli
     */
    private $db;

    /**
     * Authentication constructor.
     * @param \mysqli $db
     */
    public function __construct(\mysqli $db)
    {
        $this->db = $db;
    }

    /**
     * @param string $email
     * @param string $display
     * @param string $password
     * @param int $level
     * @return string
     * @throws \Exception
     */
    public function create($email, $display, $password, $level = self::DEFAULT_LEVEL)
    {
        if (empty($email) || empty($display) || empty($password)) {
            throw new UserCreationException();
        }

        $this->rateLimitCheck();

        $email = sha1($email);
        sodium_memzero($email);

        $display = $this->db->real_escape_string($display);

        $key = sodium_crypto_secretbox_keygen();

        $nonce = random_bytes(
            SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        );

        $password = base64_encode(
            $nonce .
            sodium_crypto_secretbox(
                $password,
                $nonce,
                $key
            )
        );

        $secret = base64_encode($key);

        $this->db->query(
            "INSERT INTO `users` (user_email_hash, user_display, user_secret, user_password, user_level) 
                VALUES 
              ('{$email}', '{$display}', '{$secret}', '{$password}', '{$level}');"
        );

        sodium_memzero($nonce);
        sodium_memzero($password);

        if (self::DUPLICATE_USER_MYSQL_ERROR == $this->db->errno) {
            throw new \Exception('User already exists');
        }

        $userId = $this->db->insert_id;

        $this->audit($userId, 'User created');

        $twoFactorKey = sha1($secret);

        sodium_memzero($secret);

        return $twoFactorKey;
    }

    /**
     * @param $email
     * @param $password
     * @return array
     * @throws \Exception
     * @throws MaxAttemptsException
     */
    public function validate($email, $password)
    {
        if (empty($email) || empty($password)) {
            throw new AuthenticationException();
        }

        $this->rateLimitCheck();

        $email = sha1($email);

        $results = $this->db->query(
            "SELECT 
                    user_id,
                    user_display, 
                    user_secret, 
                    user_password,
                    user_level
                FROM `users`
                WHERE user_email_hash = '{$email}';"
        );

        sodium_memzero($email);

        if (!$results) {
            throw new AuthenticationException();
        }

        $user = $results->fetch_assoc();

        $passwordData = base64_decode($user['user_password']);
        $secret = base64_decode($user['user_secret']);

        $user = [
            'id' => $user['user_id'],
            'user' => $user['user_password'],
            'level' => $user['user_password'],
            '2fa' => sha1($secret)
        ];

        $nonce = mb_substr($passwordData, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $encrypted = mb_substr($passwordData, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        sodium_memzero($passwordData);

        $decrypted = sodium_crypto_secretbox_open(
            $encrypted,
            $nonce,
            $secret
        );

        sodium_memzero($secret);
        sodium_memzero($nonce);

        if ($decrypted !== $password) {
            $this->audit(
                $user['id'],
                'Failed login from IP ' . $_SERVER['REMOTE_ADDR']
            );

            throw new AuthenticationException();
        }

        $this->audit(
            $user['id'],
            'Successful login from IP ' . $_SERVER['REMOTE_ADDR']
        );

        sodium_memzero($decrypted);
        sodium_memzero($password);

        return $user;
    }

    /**
     * @param int $userId
     * @param string $message
     */
    public function audit($userId, $message)
    {
        $this->db->query(
            "INSERT INTO `audit` (user_id, audit_event) 
                VALUES 
              ('{$userId}', '{$message}');"
        );
    }

    /**
     * @return bool
     * @throws MaxAttemptsException
     */
    private function rateLimitCheck()
    {
        $currentTime = new \DateTime();
        $filePath = '/tmp/' . sha1($_SERVER['REMOTE_ADDR']);

        $jsonEncoded = file_get_contents($filePath);

        $loginAttempts = [];

        if ($jsonEncoded) {
            $loginAttempts = json_decode($jsonEncoded);
        }

        $trueLoginAttempts = [
            (new \DateTime())->format(self::DATE_FORMAT)
        ];

        foreach ($loginAttempts as $attempt) {
            $pastAttemptTime = \DateTime::createFromFormat(self::DATE_FORMAT, $attempt);
            if ($currentTime->diff($pastAttemptTime)->s < self::MAX_ATTEMPTS_DURATION_IN_SECONDS) {
                $trueLoginAttempts [] = $pastAttemptTime->format(self::DATE_FORMAT);
            }
        }

        if (sizeof($trueLoginAttempts) > self::MAX_ATTEMPTS) {
            throw new MaxAttemptsException();
        }

        file_put_contents($filePath, json_encode($trueLoginAttempts, JSON_PRETTY_PRINT));

        return true;
    }
}
