<div class="sidebar-block securehandoff-sidebar" id="securehandoff-sidebar">
    <div class="sidebar-block-header">
        <h3>
            <i class="glyphicon glyphicon-lock"></i>
            {{ __('Secure Handoff') }}
        </h3>
    </div>
    <div class="sidebar-block-content">
        @if(!$configured)
            <p class="text-muted">
                {{ __('Not configured.') }}
                @if(auth()->user() && auth()->user()->isAdmin())
                    <a href="{{ route('settings', ['section' => 'securehandoff']) }}">{{ __('Settings') }}</a>
                @endif
            </p>
        @else
            @if($meta_error)
                <p class="text-danger small">{{ $meta_error }}</p>
            @endif

            <p class="text-muted small">
                {{ __('Ticket') }} #{{ $conversation->number }}
                · {{ __('id') }} {{ $conversation->id }}
            </p>

            <div id="securehandoff-requests">
                @forelse($requests as $r)
                    @include('securehandoff::partials.request_row', ['r' => $r])
                @empty
                    <p class="text-muted small securehandoff-empty">{{ __('No credential requests on this ticket yet.') }}</p>
                @endforelse
            </div>

            <form id="securehandoff-mint-form"
                  data-url="{{ route('securehandoff.mint', ['conversation' => $conversation->id]) }}">
                {{ csrf_field() }}

                <div class="form-group">
                    <label for="securehandoff-need">{{ __('What is needed') }}</label>
                    <select class="form-control input-sm" id="securehandoff-need" name="need" required>
                        @foreach($needs as $need)
                            <option value="{{ $need['id'] }}">{{ $need['label'] }}</option>
                        @endforeach
                    </select>
                </div>

                <div class="form-group">
                    <label for="securehandoff-failed">{{ __('Product path that failed') }}</label>
                    <textarea class="form-control input-sm" id="securehandoff-failed" name="failed_path" rows="2" required
                              placeholder="{{ __('e.g. connect popup never opens') }}"></textarea>
                </div>

                <div class="form-group">
                    <label for="securehandoff-bug">{{ __('Bug reference') }}</label>
                    <input type="text" class="form-control input-sm" id="securehandoff-bug" name="bug_ref" required
                           placeholder="tsk_…">
                </div>

                <div class="form-group">
                    <label for="securehandoff-ttl">{{ __('Link lifetime') }}</label>
                    <select class="form-control input-sm" id="securehandoff-ttl" name="ttl">
                        @foreach($ttls as $ttl)
                            <option value="{{ $ttl['seconds'] }}" @if((int)$ttl['seconds'] === 172800) selected @endif>
                                {{ $ttl['label'] }}
                            </option>
                        @endforeach
                    </select>
                </div>

                <p class="text-muted small">{{ __('A link cannot be minted without both a failed path and a bug reference.') }}</p>

                <button type="submit" class="btn btn-primary btn-sm btn-block" id="securehandoff-mint-btn">
                    {{ __('Mint customer link') }}
                </button>
                <div id="securehandoff-form-msg" class="margin-top-10" style="display:none;"></div>
            </form>
        @endif
    </div>
</div>
