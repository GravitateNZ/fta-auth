<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

class RecaptchaUserChecker implements \Symfony\Component\Security\Core\User\UserCheckerInterface
{

    protected RequestStack $requestStack;
    protected int $recaptchaLimit;
    protected SessionInterface $session;
    protected string $secretKey;

    /**
     * @param RequestStack $requestStack
     */
    public function __construct(SessionInterface $session, RequestStack $requestStack, int $recaptchaLimit, string $secretKey)
    {
        $this->requestStack = $requestStack;
        $this->recaptchaLimit = $recaptchaLimit;
        $this->session = $session;
        $this->secretKey = $secretKey;
    }

    public function checkPreAuth(UserInterface $user)
    {
        $loginAttempts = $this->session->get('login_attempts', 0);
        $this->session->set('login_attempts', $loginAttempts++);

        if ($loginAttempts +1 >= $this->recaptchaLimit) {
            $this->session->set('login_annoy', true);
        }

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
            throw new AuthenticationException("Cannot validate reCaptcha response");
        }

        $result = json_decode($result);
        if (!($result && $result->success)) {
            throw new AuthenticationException("Please try again");
        }

    }

    public function checkPostAuth(UserInterface $user)
    {
        //reset it when we login
        $loginAttempts = $this->session->set('login_attempts', 0);
        $this->session->set('login_annoy', false);

    }
}
