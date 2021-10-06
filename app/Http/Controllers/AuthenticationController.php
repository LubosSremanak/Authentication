<?php

namespace App\Http\Controllers;

use App\Http\Requests\UserLoginRequest;
use App\Http\Requests\UserRegisterRequest;
use App\Models\User;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class AuthenticationController extends Controller
{


    public function login(UserLoginRequest $request)
    {
        $validatedRequest = $request->validated();
        $userModel = new User();
        $user = $userModel->findUserByEmail($validatedRequest['email']);
        $response = [
            'message' => 'Wrong username or password',
        ];
        if ($userModel->isWrongPassword($user, $validatedRequest['password'])) {
            return response($response, 401);
        }

        $token = $user->createToken('jwttoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token,
            'message' => 'User logged in',
        ];

        return response($response, 201);
    }

    public function logout()
    {
        $userModel = new User();
        $userModel->deleteUser();
        $response = [
            'message' => 'User logged out',
        ];

        return response($response, 201);
    }

    public function register(UserRegisterRequest $request)
    {
        $validatedRequest = $request->validated();
        $userModel = new User();
        $user = $userModel->createUser($validatedRequest);
        $token = $user->createToken('jwttoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token,
            'message' => 'User successfully registered',
        ];
        return response($response, 201);
    }

}
