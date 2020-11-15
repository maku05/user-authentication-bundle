# User Authenticatoin Bundle

## description

This is a simple user authentication bundle by which a user can be created and a token for this user will be generated.

## features

- user creation and deletion
- token as jwt

## installation

### get the bundle

`composer require maku05/user-authenticataion-bundle`


### generate ssh keys
 
form [lexik/jwt-authentication-bundle](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/index.md#getting-started)

``` bash
$ mkdir -p config/jwt
$ openssl genpkey -out config/jwt/private.pem -aes256 -algorithm rsa -pkeyopt rsa_keygen_bits:4096
$ openssl pkey -in config/jwt/private.pem -out config/jwt/public.pem -pubout
```

### config the security.yml

`config/packages/security.yml`

```yaml
security:
    encoders:
        Maku05\UserAuthenticationBundle\Entity\User:
            algorithm: auto
    # https://symfony.com/doc/current/security.html#where-do-users-come-from-user-providers
    providers:
        app_user_provider:
            entity:
                class: Maku05\UserAuthenticationBundle\User
                property: email
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        api:
            pattern: ^/api
            anonymous: true
            stateless: true
            provider: app_user_provider
            guard:
                authenticators:
                    - Maku05\UserAuthenticationBundle\Security\JwtTokenAuthenticator
        main:
            anonymous: true
            lazy: true
            provider: app_user_provider
```

### config your fos_rest.yml

```yaml
fos_rest:
  view:
    view_response_listener: true
  format_listener:
    rules:
      - { path: '^/api', priorities: ['json'], fallback_format: json, prefer_extension: true }
      - { path: '^/', priorities: ['text/html'], fallback_format: html, prefer_extension: true }
```

### create user table in database

You can add the annotation migration from this bundle to the project doctrine.yml

```yaml
mappings:
    UserAuthenticationBundle:
        is_bundle: true
        type: annotation
        dir: 'Entity'
        prefix: 'Maku05\UserAuthenticationBundle\Entity'
        alias: UserAuthentitcation
```

After this head to the console

To create the migration for the user table
```bash
$ bin/console make:migration
```

To execute the migration

```bash
bin/console doctrine:migrations:migrate
```
