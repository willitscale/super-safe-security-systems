# SuperSafeSecuritySystemsAuthentication

### Disclaimer

This is **NOT** a library which should be used for commercial purposes or in any means to protect sensitive data as it was written with a backdoor for a CTF (Capture the Flag) hacking challenge.

### Setup 

Include this by adding the following to your `composer.json`:

```javascript
{
    "repositories": [
        {
            "url": "https://github.com/willitscale/super-safe-security-systems.git",
            "type": "git"
        }
    ],
    "require": {
        "super-safe-security-systems/super-safe-security-systems": "master"
    }
}
```

Create a database from the dump with the following command:

```bash
mysql -u username -p < dump.sql
```

Create a database user limited to only the `secure_auth` database only with `SELECT`, `INSERT` and `UPDATE` permissions:

```sql
GRANT INSERT, SELECT, UPDATE ON secure_auth.* TO 'secure_auth' IDENTIFIED BY 'secure_password';

```

