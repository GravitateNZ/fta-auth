<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class AuthenticationFailureLockoutListener
{
    protected UserProviderInterface $userProvider;

    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    public function lockoutHandler(AuthenticationFailureEvent $event): void
    {
        $token = $event->getAuthenticationToken();
        $username = $token->getUsername();

        $user = $this->userProvider->loadUserByUsername($username);
        if (! $user instanceof LockableUserInterface){
            throw new UnsupportedUserException("User must implement LockableUser");
        }

        $user->incrementFailedLogins(new \DateTime());
    }

}
