<?php


namespace Maku05\UserAuthenticationBundle\Controller;


use Maku05\UserAuthenticationBundle\Entity\User;
use Maku05\UserAuthenticationBundle\Repository\UserRepository;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use FOS\RestBundle\Controller\Annotations as Rest;
use Symfony\Component\Routing\Annotation\Route;


/**
 * @Route("/api", name="api_token")
 * Class TokenController
 * @package App\Controller
 */
class TokenController extends AbstractController
{
    /**
     * @var TranslatorInterface
     */
    protected TranslatorInterface $translator;
    /**
     * @var UserRepository
     */
    private UserRepository $userRepository;
    /**
     * @var UserPasswordEncoderInterface
     */
    private UserPasswordEncoderInterface $passwordEncoder;
    /**
     * @var JWTEncoderInterface
     */
    private JWTEncoderInterface $jwtEncoder;

    public function __construct(UserRepository $userRepository, UserPasswordEncoderInterface $passwordEncoder, JWTEncoderInterface $jwtEncoder, TranslatorInterface $translator)
    {
        $this->userRepository = $userRepository;
        $this->passwordEncoder = $passwordEncoder;
        $this->jwtEncoder = $jwtEncoder;
        $this->translator = $translator;
    }

    /**
     * @Rest\Post("/token")
     */
    public function postCreateTokenAction(Request $request)
    {
        if(null === ($user = $this->userRepository->findOneBy(['email' => $request->getUser()]))) {
            return $this->getApiJsonResponse(['error' => $this->translator->trans('finance.user.message.error.email.notFound')],Response::HTTP_NOT_FOUND);
        }

        if(!$this->passwordEncoder->isPasswordValid($user, $request->getPassword())) {
            return $this->getApiJsonResponse(['error' => $this->translator->trans('finance.user.message.error.password.wrong')],Response::HTTP_UNAUTHORIZED);
        }

        return $this->getApiJsonResponse([
            'success' => true,
            'token' => $this->getToken($user)
        ], Response::HTTP_OK);
    }


    public function getToken(User $user)
    {
        return $this->jwtEncoder->encode([
            'email' => $user->getEmail(),
            'exp' => time() + $_ENV['JWT_TTL']
        ]);
    }

    /**
     * return a json formatted response
     *
     * @param $content
     * @param string $status
     * @param array $headers
     * @param array $context
     * @return Response
     */
    protected function getApiJsonResponse($content, string $status, array $headers = [], array $context = []): JsonResponse
    {
        return $this->json($content, $status, $headers, $context);
    }
}