<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Duo\DuoUniversal\Client;
use MillenniumFalcon\Core\ORM\User;
use Symfony\Bundle\SecurityBundle\Security\FirewallConfig;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Event\AuthenticationEvent;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\FirewallMapInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Twig\Token;

class DuoAuthHandler implements LogoutHandlerInterface
{

    protected RequestStack $requestStack;
    protected TokenStorageInterface $tokenStorage;
    protected FirewallMap $firewallMap;
    protected Client $duoClient;

    public function __construct(
        RequestStack $requestStack,
        TokenStorageInterface $tokenStorage,
        Client $duoClient
    )  {
        $this->requestStack = $requestStack;
        $this->tokenStorage = $tokenStorage;
        $this->duoClient = $duoClient;
    }

    public function handler(RequestEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $token = $this->tokenStorage->getToken();

        if (!$token || $token instanceof AnonymousToken || !$token->isAuthenticated()) {
            return;
        }

        $session = $request->getSession();
        $username = $token->getUsername();

        //1. if the session has no duotoken.. then we will create one and redirect.
        try {

            if ($session->get('duo_token')) {
                // how do we verify a token? do we need to?
                // and every request?
                return;
            } else if ($session->has('duo_state') && ($redirectUrl = $session->get('duo_redirect_url')) && ($code = $request->get('duo_code')) && ($state = $request->get('state'))) {
                // if we state then we are waiting for a response...
                // xdebug_break();

                if ($state !== $session->get('duo_state')) {
                    throw new AccessDeniedException();
                }

                $this->duoClient->redirect_url = $redirectUrl;

                $token = $this->duoClient->exchangeAuthorizationCodeFor2FAResult(
                    $code,
                    $username,
//                    $state
                );

                $session->set('duo_token', $token);

            } else if (!$session->has('duo_token')) {
                // no token... do a thing
                $state = bin2hex(random_bytes(64));
                $session->set('duo_state', $state);

                $this->duoClient->healthCheck();
                $redirectUrl = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();
                $session->set('duo_redirect_url', $redirectUrl);
                $this->duoClient->redirect_url = $redirectUrl;

                $url = $this->duoClient->createAuthUrl(
                    $username,
                    $state
                );

                $event->setResponse(
                    new RedirectResponse(
                        $url,
                        Response::HTTP_FOUND
                    )
                );

            } else {
                throw new AccessDeniedException();
            }
        } catch (\Throwable $e) {

            // no duo.. throw an access denied
            $session->clear('duo_token');
            $session->clear('duo_state');
            $session->clear('duo_redirect_url');

            throw $e;
        }
    }


    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        if (!$request->hasSession()) {
            return;
        }

        $session = $request->getSession();

        if ($session->has('duo_state')) {
            $session->remove('duo_state');
        }

        if ($session->has('duo_token')) {
            $session->remove('duo_token');
        }
    }
}
