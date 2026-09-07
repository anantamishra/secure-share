<?php

use Illuminate\Support\Facades\Route;

Route::group([
    'middleware' => ['web', 'auth'],
    'prefix'     => \Helper::getSubdirectory(),
    'namespace'  => 'Modules\SecureHandoff\Http\Controllers',
], function () {
    Route::post('/securehandoff/mint/{conversation}', 'SecureHandoffController@mint')
        ->name('securehandoff.mint')
        ->where('conversation', '[0-9]+');
    Route::post('/securehandoff/test', 'SecureHandoffController@test')
        ->name('securehandoff.test');
});
