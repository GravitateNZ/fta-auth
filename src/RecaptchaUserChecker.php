<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

class RecaptchaUserChecker implements \Symfony\Component\Security\Core\User\UserCheckerInterface
{

    use FirewallContextTrait;

    protected RequestStack $requestStack;
    protected int $recaptchaLimit;
    protected SessionInterface $session;
    protected string $secretKey;

    /**
     * @param RequestStack $requestStack
     */
    public function __construct(
        SessionInterface $session,
        RequestStack $requestStack,
        int $recaptchaLimit,
        string $secretKey
    )
    {
        $this->requestStack = $requestStack;
        $this->recaptchaLimit = $recaptchaLimit;
        $this->session = $session;
        $this->secretKey = $secretKey;
    }

    public function checkPreAuth(UserInterface $user)
    {

        $firewallName = $this->getFirewallNameFromContext();
        $k = $firewallName . "_login_attempts";
        $loginAttempts = $this->session->get($k, 0);

        if ($loginAttempts < $this->recaptchaLimit) {
            return;
        }

        $request = $this->requestStack->getCurrentRequest();

        $opts = [
            'http' => [
                'timeout' => 10,
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => http_build_query([
                    'response' => $request->get('g-recaptcha-response'),
                    'secret' => $this->secretKey,
                    'remoteip' => $request->getClientIp()
                ]),
            ]
        ];

        $result = file_get_contents(
            'https://www.google.com/recaptcha/api/siteverify',
            false,
            stream_context_create($opts)
        );

        if (!$result) {
            throw new AuthenticationException("Please try again");
        }

        $result = json_decode($result);
        if (!($result && $result->success)) {
            throw new AuthenticationException("Please try again");
        }

    }

    public function checkPostAuth(UserInterface $user)
    {
        //reset it when we login
        $firewallName = $this->getFirewallNameFromContext();
        $loginAttempts = $this->session->set($firewallName . '_login_attempts', 0);
        $this->session->set($firewallName . '_login_annoy', false);
    }
}
