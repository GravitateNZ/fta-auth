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
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Firewall;

class AuthenticationFailureLockoutListener
{
    use FirewallContextTrait;

    protected UserProviderInterface $userProvider;
    protected RequestStack $requestStack;
    protected string $firewallName;
    protected int $lockoutCount;

    public function __construct(
        UserProviderInterface $userProvider,
        RequestStack $requestStack,
        string $firewallName,
        int $lockoutCount
    ) {
        $this->userProvider = $userProvider;
        $this->requestStack = $requestStack;
        $this->firewallName = $firewallName;
        $this->lockoutCount = $lockoutCount;
    }

    public function lockoutHandler(AuthenticationFailureEvent $event): void
    {
        if ($this->getFirewallNameFromContext() !== $this->firewallName) {
            return;
        }
        
        $token = $event->getAuthenticationToken();
        $username = $token->getUsername();
        $session = $this->requestStack->getCurrentRequest()->getSession();
        $k = "{$username}_{$this->firewallName}_logincount";
        [$failedCount, $lockoutCount] = $session->get($k, [0, $this->lockoutCount]);

        $user = null;
        try {
            $user = $this->userProvider->loadUserByUsername($username);
            if ($user instanceof LockableUserInterface) {
                $failedCount = $user->getFailedLoginCount();
            }
        } catch (UsernameNotFoundException $usernameNotFoundException){}

        $failedCount++;

        $session->set($k, [$failedCount, $this->lockoutCount]);

        if ($user) {
            if($user instanceof LockableUserInterface) {
                $dt = new \DateTime();
                $user->incrementFailedLogins($dt);
                $user->isLocked($this->lockoutCount, $dt);
            } else {
                throw new UnsupportedUserException("User must implement LockableUser");
            }
        }
    }

}
