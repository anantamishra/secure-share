@php
    $status = $r['status'] ?? '';
    $url = $r['url'] ?? '';
    $need = $r['need_label'] ?? ($r['need'] ?? '');
    $exp = !empty($r['expires_at']) ? gmdate('Y-m-d H:i', (int)$r['expires_at']) . ' UTC' : '';
@endphp
<div class="securehandoff-request" data-id="{{ $r['id'] ?? '' }}">
    <div class="securehandoff-request-head">
        <span class="label label-{{ $status === 'submitted' ? 'success' : ($status === 'pending' ? 'warning' : ($status === 'read' ? 'default' : 'danger')) }}">
            {{ $status }}
        </span>
        <span class="securehandoff-need">{{ $need }}</span>
    </div>
    @if($exp)
        <div class="text-muted small">{{ __('Expires') }} {{ $exp }}</div>
    @endif
    @if($url && $status === 'pending')
        <div class="securehandoff-url-row">
            <input type="text" class="form-control input-sm securehandoff-url" value="{{ $url }}" readonly>
            <button type="button" class="btn btn-default btn-xs securehandoff-copy" data-copy="{{ $url }}">{{ __('Copy') }}</button>
            <button type="button" class="btn btn-default btn-xs securehandoff-insert" data-copy="{{ $url }}">{{ __('Insert into reply') }}</button>
        </div>
    @endif
</div>
