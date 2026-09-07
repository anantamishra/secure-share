<?php

namespace Modules\SecureHandoff;

/**
 * Server-side client for the handoff staff API. The Bearer token never
 * leaves PHP — conversation JS only talks to this module's own routes.
 */
class Client
{
    /**
     * @param string               $method GET or POST
     * @param string               $path   e.g. /api/v1/me
     * @param array<string,mixed>|null $json
     * @return array{ok:bool,code:int,body:array,error:?string}
     */
    public static function request($method, $path, $json = null)
    {
        $base = self::baseUrl();
        $token = self::token();
        if ($base === '' || $token === '') {
            return ['ok' => false, 'code' => 0, 'body' => [], 'error' => __('Handoff URL and API token are not set.')];
        }

        $err = self::urlError($base);
        if ($err !== null) {
            return ['ok' => false, 'code' => 0, 'body' => [], 'error' => $err];
        }

        $url = $base . $path;
        $ch = curl_init($url);
        $headers = [
            'Accept: application/json',
            'Authorization: Bearer ' . $token,
        ];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER     => $headers,
        ];
        if (strtoupper($method) === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = json_encode($json === null ? new \stdClass() : $json);
            $headers[] = 'Content-Type: application/json';
            $opts[CURLOPT_HTTPHEADER] = $headers;
        }
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            return ['ok' => false, 'code' => $code, 'body' => [], 'error' => $cerr !== '' ? $cerr : __('Could not reach the handoff app.')];
        }

        $body = json_decode((string) $raw, true);
        if (!is_array($body)) {
            $body = [];
        }

        $ok = $code >= 200 && $code < 300 && !empty($body['ok']);
        $error = null;
        if (!$ok) {
            $error = $body['error']['message'] ?? ('HTTP ' . $code);
        }

        return ['ok' => $ok, 'code' => $code, 'body' => $body, 'error' => $error];
    }

    public static function configured()
    {
        return self::baseUrl() !== '' && self::token() !== '';
    }

    public static function baseUrl()
    {
        return rtrim((string) \Option::get('securehandoff.api_url'), '/');
    }

    public static function token()
    {
        $raw = (string) \Option::get('securehandoff.api_token');
        if ($raw === '') {
            return '';
        }
        if (class_exists('\Helper')) {
            $dec = \Helper::decrypt($raw);
            if (is_string($dec) && strpos($dec, 'iwp_') === 0) {
                return $dec;
            }
        }
        return $raw;
    }

    /**
     * @return string|null
     */
    public static function urlError($url)
    {
        $p = parse_url($url);
        if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
            return __('Handoff URL must be an absolute http(s) URL.');
        }
        $scheme = strtolower((string) $p['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            return __('Handoff URL must use http or https.');
        }
        if (!empty($p['user']) || !empty($p['pass'])) {
            return __('Handoff URL must not include credentials.');
        }
        return null;
    }
}
