<?php declare(strict_types=1);

namespace GravitateNZ\fta\auth\Security\tests;

trait RequestStackTrait
{

    public function getRequestStack(): \Symfony\Component\HttpFoundation\RequestStack
    {

        $requestStack = new \Symfony\Component\HttpFoundation\RequestStack();
        $request = new \Symfony\Component\HttpFoundation\Request();
        $session = new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage());
        $request->setSession($session);
        $request->attributes->set('_firewall_context','security.firewall.map.context.test');

        $requestStack->push($request);

        return $requestStack;
    }


}