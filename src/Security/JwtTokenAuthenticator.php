<?php


namespace Maku05\UserAuthenticationBundle\Security;


use Maku05\UserAuthenticationBundle\Repository\UserRepository;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JwtTokenAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var JWTEncoderInterface
     */
    private JWTEncoderInterface $jwtEncoder;
    /**
     * @var UserRepository
     */
    private UserRepository $userRepository;

    public function __construct(JWTEncoderInterface $jwtEncoder, UserRepository $userRepository)
    {
        $this->jwtEncoder = $jwtEncoder;
        $this->userRepository = $userRepository;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return $this->getAuthenticatorJsonResponse(['error' => 'You are not authorized.'], Response::HTTP_UNAUTHORIZED);
    }

    public function supports(Request $request)
    {
        return true;
    }

    public function getCredentials(Request $request)
    {
        $extractor = new AuthorizationHeaderTokenExtractor('Bearer', 'Authorization');

        if(!($token = $extractor->extract($request))) {
            return $this->start($request);
        }

        return $token;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $data = $this->jwtEncoder->decode($credentials);
        } catch (JWTFailureException $e) {
            throw new CustomUserMessageAuthenticationException('Invalid token');
        }

        return $this->userRepository->findOneBy(['email' => $data['email']]);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // TODO: Implement onAuthenticationFailure() method.
    }


    public function supportsRememberMe()
    {
        return false;
    }

    protected function getAuthenticatorJsonResponse(array $content, string $status): JsonResponse
    {
        return new JsonResponse($content, $status);
    }
}