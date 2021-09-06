# fta-auth

Simple helpers for augmenting authentication such as account lockout


Currently implements a simple lockout mechanism, a recaptcha checker and a way of chaining. These will probably go away when Symfony 5.4 or 6.0 is release

Configure the lister with a user provider then attach the User checker to a firewall.

```yaml
    firewalls:
        manage:
            anonymous: ~
            pattern: ^/manage
            form_login:
                provider: manage
                check_path: /manage/login_check
                login_path: /manage/login
                default_target_path: /manage/after-login

            user_checker: userchecker.chain
```

```yaml
    userchecker.locked_user:
      class: 'GravitateNZ\fta\auth\Security\UserLockedUserChecker'
      arguments:
        $lockoutCount: 10
        $interval: "PT12H"

    userchecker.recaptcha:
      class: 'GravitateNZ\fta\auth\Security\RecaptchaUserChecker'
      arguments:
        $recaptchaLimit: 1
        $secretKey: '%env(RECAPTCHA_SECRET_KEY)%'

    userchecker.chain:
      class: 'GravitateNZ\fta\auth\Security\ChainUserChecker'
      arguments:
        $userCheckers:
          - '@userchecker.locked_user'
          - '@userchecker.recaptcha'
```
(c) 2021 Gravitate
