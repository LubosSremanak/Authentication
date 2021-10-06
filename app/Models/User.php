<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var string[]
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];


    public function deleteUser(): void
    {
        auth()->user()->tokens()->delete();
    }


    public function findUserByEmail($email)
    {
        return User::where('email', $email)->first();
    }

    public function isWrongPassword($user, $password): bool
    {
        return (!$user || !Hash::check($password, $user->password));
    }

    public function createUser($validatedRequest)
    {
        return User::create([
            'name' => $validatedRequest['name'],
            'email' => $validatedRequest['email'],
            'password' => Hash::make($validatedRequest['password'])
        ]);
    }
}
