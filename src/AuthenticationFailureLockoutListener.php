<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Bundle\SecurityBundle\Security\FirewallConfig;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Firewall;

class AuthenticationFailureLockoutListener
{
    protected UserProviderInterface $userProvider;
    protected FirewallConfig $firewallConfig;
    protected RequestStack $requestStack;
    protected FirewallMap $firewallMap;

    public function __construct(FirewallMap $firewallMap, FirewallConfig $firewallConfig, UserProviderInterface $userProvider, RequestStack $requestStack)
    {
        $this->firewallConfig = $firewallConfig;
        $this->userProvider = $userProvider;
        $this->requestStack = $requestStack;
        $this->firewallMap = $firewallMap;
    }

    public function lockoutHandler(AuthenticationFailureEvent $event): void
    {

        $config = $this->firewallMap->getFirewallConfig($this->requestStack->getCurrentRequest());
        if ($config !== $this->firewallConfig) {
            return;
        }

        $token = $event->getAuthenticationToken();
        $username = $token->getUsername();

        $user = $this->userProvider->loadUserByUsername($username);
        if (! $user instanceof LockableUserInterface){
            throw new UnsupportedUserException("User must implement LockableUser");
        }

        $user->incrementFailedLogins(new \DateTime());
    }

}
