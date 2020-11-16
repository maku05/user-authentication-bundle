<?php


namespace Maku05\UserAuthenticationBundle\Controller;


use Maku05\UserAuthenticationBundle\Entity\User;
use Maku05\UserAuthenticationBundle\Repository\UserRepository;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Symfony\Component\Routing\Annotation\Route;
use FOS\RestBundle\Controller\Annotations as Rest;

/**
 * @Route("/api", name="api_")
 *
 * Class UserController
 * @package App\Controller
 */
class UserController extends AbstractController
{
    const AUTHENTICATION_PASSWORD_MIN_LENGTH = 8;

    /**
     * @var TranslatorInterface
     */
    protected TranslatorInterface $translator;
    /**
     * @var EntityManagerInterface
     */
    protected EntityManagerInterface $manager;
    /**
     * @var UserPasswordEncoderInterface
     */
    protected UserPasswordEncoderInterface $passwordEncoder;
    /**
     * @var UserRepository
     */
    protected UserRepository $userRepository;
    /**
     * @var TokenController
     */
    protected TokenController $tokenController;

    public function __construct(EntityManagerInterface $manager, UserPasswordEncoderInterface $passwordEncoder, UserRepository $userRepository, TranslatorInterface $translator, TokenController $tokenController)
    {
        $this->manager          = $manager;
        $this->passwordEncoder  = $passwordEncoder;
        $this->userRepository = $userRepository;
        $this->translator = $translator;
        $this->tokenController = $tokenController;
    }

    /**
     * delete the user if it exists
     *
     * @Rest\Delete("/user/{id}")
     * @param int $id
     */
    public function deleteRemoveUserAction(int $id): JsonResponse
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        if(null === ($user = $this->userRepository->findOneBy(['id' => $id]))) {
            return $this->getApiJsonResponse(['error' => 'User not found.'], Response::HTTP_NOT_FOUND);
        }

        $this->manager->remove($user);
        $this->manager->flush();

        return $this->getApiJsonResponse(['success' => 'User removed successfully.', 'user' => $user], Response::HTTP_OK, [], ['groups' => ['api']]);
    }



    /**
     * create a new user
     * give error messages for bad requests
     *
     * @Rest\Post("/user")
     *
     * @param Request $request
     */
    public function postCreateUserAction(Request $request): JsonResponse
    {
        if(!$request->get('password') || !$request->get('passwordConfirmation') || !$request->get('email')) {
            return $this->getApiJsonResponse([
                'error' => 'data_insufficient',
                'message' => 'The given data is insufficient. Please make shure to give a email, password, password confirmation.',
            ], Response::HTTP_BAD_REQUEST);
        }

        if(self::AUTHENTICATION_PASSWORD_MIN_LENGTH > strlen($request->get('password'))) {
            return $this->getApiJsonResponse([
                'error' => 'password_length',
                'message' => 'The given password must be at least 8 characters'
            ], Response::HTTP_BAD_REQUEST);
        }

        if($request->get('password') != $request->get('passwordConfirmation')) {
            return $this->getApiJsonResponse([
                'error' => 'wrong_password',
                'message' => 'The password confirmation is not equal to the given password'
            ], Response::HTTP_BAD_REQUEST);
        }

        $user = new User();
        $user->setEmail($request->get('email'));
        $user->setPassword($this->getEncodedPassword($user, $request->get('password')));

        try {
            $this->manager->persist($user);
            $this->manager->flush();
        } catch (UniqueConstraintViolationException $e) {
            return $this->getApiJsonResponse([
                'error' => 'user_exists',
                'message' => $e->getMessage()
            ], Response::HTTP_CONFLICT);
        }

        return $this->getApiJsonResponse([
            'success' => 'User created',
            ], Response::HTTP_CREATED);
    }



    /**
     * @param User $user
     * @param string $password
     * @return string
     */
    protected function getEncodedPassword(User $user, string $password): string
    {
        return $this->passwordEncoder->encodePassword($user, $password);
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