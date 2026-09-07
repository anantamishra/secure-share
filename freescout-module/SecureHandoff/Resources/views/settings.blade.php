<div class="col-xs-12">
    <form class="form-horizontal margin-top" method="POST" action="">
        {{ csrf_field() }}

        <div class="form-group">
            <label for="securehandoff_api_url" class="col-sm-2 control-label">{{ __('Handoff URL') }}</label>
            <div class="col-sm-6">
                <input type="url" class="form-control" name="settings[securehandoff.api_url]" id="securehandoff_api_url"
                       value="{{ old('settings.securehandoff.api_url', $settings['securehandoff.api_url'] ?? '') }}"
                       placeholder="https://handoff.example.com" autocomplete="off">
                <p class="form-help">
                    {{ __('The APP_URL of the secure credential handoff app. Do not append /api.') }}
                </p>
            </div>
        </div>

        <div class="form-group">
            <label for="securehandoff_api_token" class="col-sm-2 control-label">{{ __('API token') }}</label>
            <div class="col-sm-6">
                <input type="password" class="form-control" name="settings[securehandoff.api_token]" id="securehandoff_api_token"
                       value="{{ old('settings.securehandoff.api_token', $settings['securehandoff.api_token'] ?? '') }}"
                       placeholder="iwp_…" autocomplete="new-password">
                <p class="form-help">
                    {{ __('Minted on the handoff host with') }}
                    <code>php bin/staff.php token you@instawp.com</code>.
                    {{ __('Leave blank to keep the current token.') }}
                </p>
                <div id="securehandoff-test-result" class="margin-top-10" style="display:none;"></div>
            </div>
            <div class="col-sm-2">
                <button type="button" class="btn btn-default" id="securehandoff-test"
                        data-url="{{ route('securehandoff.test') }}">
                    <i class="glyphicon glyphicon-ok"></i> {{ __('Test connection') }}
                </button>
            </div>
        </div>

        <div class="form-group">
            <div class="col-sm-6 col-sm-offset-2">
                <p class="text-muted">
                    {{ __('This module mints customer links. Credentials are never shown in FreeScout — open the handoff app to read a submitted secret once.') }}
                    {{ __('If FREESCOUT_API_URL / FREESCOUT_API_KEY are set on the handoff host, minting also posts an internal note on this conversation (using the conversation id, the number in the URL).') }}
                </p>
            </div>
        </div>

        <div class="form-group">
            <div class="col-sm-6 col-sm-offset-2">
                <button type="submit" class="btn btn-primary">{{ __('Save') }}</button>
            </div>
        </div>
    </form>
</div>
