<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(RegisterRequest $request){
        $paload = $request->validated();

        try {
            $paload["password"] = Hash::make($paload["password"]);
            User::create($paload);
            return response()->json(["message"=> "Accounte created successfully!"], 200);
        } catch (\Exception $err) {
            Log::info("Register error =>".$err->getMessage());
            return response()->json(["message"=> "Some this went wrong please try again later!"], 500);
        }

    }

    public function login(Request $request){
        $payload = $request->validate([
            "email" => "required|email",
            "password" => "required",
        ]);

        try {
            $user = User::where("email", $payload["email"])->first();
            if($user){
                // * check password
                if(!Hash::check($payload["password"], $user->password)){
                    return response()->json(["message"=> "Invalid credentials"], 401);
                }
                $token = $user->createToken("web")->plainTextToken;
                $authRes = array_merge($user->toArray(), ["token" => $token]);
                return response()->json(["message" => "Logged in successfully!", "users" => $authRes]);
            }
            return response()->json(["message"=> "Invalid credentials"], 401);
        } catch (\Exception $err) {
            Log::info("Login error =>".$err->getMessage());
            return response()->json(["message"=> "Some this went wrong please try again later!"], 500);
        }
    }

    public function checkCredentials(Request $request){
        $payload = $request->validate([
            "email" => "required|email",
            "password" => "required",
        ]);

        try {
            $user = User::where("email", $payload["email"])->first();
            if($user){
                // * check password
                if(!Hash::check($payload["password"], $user->password)){
                    return response()->json(["message"=> "Invalid credentials"], 401);
                }
                return response()->json([ "status" => 200,  "message" => "Logged in successfully!"]);
            }
            return response()->json(["message"=> "Invalid credentials"], 401);
        } catch (\Exception $err) {
            Log::info("Login credentials error =>".$err->getMessage());
            return response()->json(["message"=> "Some this went wrong please try again later!"], 500);
        }
    }

}
