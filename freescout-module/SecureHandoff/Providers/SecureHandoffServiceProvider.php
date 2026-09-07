<?php

namespace Modules\SecureHandoff\Providers;

use Illuminate\Support\ServiceProvider;
use Modules\SecureHandoff\Client;

class SecureHandoffServiceProvider extends ServiceProvider
{
    const MODULE = 'securehandoff';

    public function boot()
    {
        $this->loadViewsFrom(__DIR__ . '/../Resources/views', self::MODULE);
        $this->loadRoutesFrom(__DIR__ . '/../Http/routes.php');
        $this->registerHooks();
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../Config/config.php', self::MODULE);
    }

    protected function registerHooks()
    {
        \Eventy::addFilter('stylesheets', function ($styles) {
            $path = \Module::getPublicPath(self::MODULE) . '/css/module.css';
            if (file_exists(public_path($path))) {
                $styles[] = $path;
            }
            return $styles;
        });

        \Eventy::addFilter('javascripts', function ($javascripts) {
            $path = \Module::getPublicPath(self::MODULE) . '/js/module.js';
            if (file_exists(public_path($path))) {
                $javascripts[] = $path;
            }
            return $javascripts;
        });

        \Eventy::addFilter('settings.sections', function ($sections) {
            $sections[self::MODULE] = [
                'title' => __('Secure Handoff'),
                'icon'  => 'lock',
                'order' => 450,
            ];
            return $sections;
        }, 30);

        \Eventy::addFilter('settings.section_settings', function ($settings, $section) {
            if ($section !== self::MODULE) {
                return $settings;
            }
            return [
                'securehandoff.api_url'   => \Option::get('securehandoff.api_url'),
                'securehandoff.api_token' => \Option::get('securehandoff.api_token') ? '********' : '',
            ];
        }, 20, 2);

        \Eventy::addFilter('settings.section_params', function ($params, $section) {
            if ($section !== self::MODULE) {
                return $params;
            }
            $params['settings'] = [
                'securehandoff.api_url' => [],
                'securehandoff.api_token' => [
                    'encrypt'       => true,
                    'safe_password' => true,
                ],
            ];
            return $params;
        }, 20, 2);

        \Eventy::addFilter('settings.view', function ($view, $section) {
            return $section === self::MODULE ? self::MODULE . '::settings' : $view;
        }, 20, 2);

        \Eventy::addFilter('settings.before_save', function ($request, $section) {
            if ($section !== self::MODULE) {
                return $request;
            }
            $settings = $request->settings ?: [];
            if (!empty($settings['securehandoff.api_url'])) {
                $settings['securehandoff.api_url'] = rtrim($settings['securehandoff.api_url'], '/');
            }
            $request->merge(['settings' => $settings]);
            return $request;
        }, 20, 3);

        \Eventy::addAction('conversation.after_prev_convs', function ($customer, $conversation, $mailbox) {
            try {
                if (!$conversation) {
                    return;
                }
                $configured = Client::configured();
                $user = auth()->user();
                if (!$configured && (!$user || !$user->isAdmin())) {
                    return;
                }

                $needs = [];
                $ttls = [];
                $requests = [];
                $meta_error = null;

                if ($configured) {
                    $meta = Client::request('GET', '/api/v1/meta');
                    if ($meta['ok'] && !empty($meta['body']['data']['needs'])) {
                        $needs = $meta['body']['data']['needs'];
                        $ttls = $meta['body']['data']['ttl'] ?? [];
                    } else {
                        $meta_error = $meta['error'];
                        $needs = [
                            ['id' => 'wp_admin', 'label' => 'WordPress administrator account (temporary)'],
                            ['id' => 'wp_app_password', 'label' => 'WordPress application password'],
                        ];
                        $ttls = [
                            ['seconds' => 3600, 'label' => '1 hour'],
                            ['seconds' => 21600, 'label' => '6 hours'],
                            ['seconds' => 86400, 'label' => '24 hours'],
                            ['seconds' => 172800, 'label' => '48 hours'],
                        ];
                    }

                    $list = Client::request('GET', '/api/v1/requests?ticket_id=' . urlencode((string) $conversation->id));
                    if ($list['ok'] && !empty($list['body']['data']) && is_array($list['body']['data'])) {
                        $requests = $list['body']['data'];
                    }
                }

                echo \View::make(self::MODULE . '::partials.sidebar', [
                    'conversation' => $conversation,
                    'configured'   => $configured,
                    'needs'        => $needs,
                    'ttls'         => $ttls,
                    'requests'     => $requests,
                    'meta_error'   => $meta_error,
                ])->render();
            } catch (\Exception $e) {
                \Helper::logException($e);
            }
        }, 20, 3);
    }
}
