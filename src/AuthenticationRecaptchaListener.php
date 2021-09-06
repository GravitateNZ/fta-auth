<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use MongoDB\Driver\Session;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class AuthenticationRecaptchaListener
{

    use FirewallContextTrait;

    protected RequestStack $requestStack;
    protected string $firewallName;
    protected int $recaptchaLimit;

    public function __construct(
        RequestStack $requestStack,
        string $firewallName,
        int $recaptchaLimit
    ) {
        $this->requestStack = $requestStack;
        $this->firewallName = $firewallName;
        $this->recaptchaLimit = $recaptchaLimit;
    }


    public function recaptchaHandler(AuthenticationFailureEvent $event): void
    {
        if ($this->getFirewallNameFromContext() !== $this->firewallName) {
            return;
        }

        $request = $this->requestStack->getCurrentRequest();

        $key = $this->firewallName . '_login_attempts';
        $loginAttempts = $request->getSession()->get($key, 0) + 1;
        $request->getSession()->set($key, $loginAttempts);

        if ($loginAttempts >= $this->recaptchaLimit) {
            $request->getSession()->set($this->firewallName . '_login_annoy', true);
        }
    }

    
}