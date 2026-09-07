(function ($) {
    'use strict';

    function csrf() {
        var $meta = $('meta[name="csrf-token"]');
        return $meta.length ? $meta.attr('content') : $('input[name="_token"]').val();
    }

    function flash($el, kind, text) {
        $el.removeClass('alert alert-success alert-danger')
            .addClass('alert alert-' + kind)
            .text(text)
            .show();
    }

    function copyText(text, $btn) {
        function done() {
            var prev = $btn.text();
            $btn.text('Copied');
            setTimeout(function () { $btn.text(prev); }, 1500);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () {
                fallbackCopy(text);
                done();
            });
        } else {
            fallbackCopy(text);
            done();
        }
    }

    function fallbackCopy(text) {
        var $tmp = $('<textarea>').val(text).css({ position: 'fixed', left: '-9999px' }).appendTo('body');
        $tmp[0].select();
        try { document.execCommand('copy'); } catch (e) { /* ignore */ }
        $tmp.remove();
    }

    function insertReply(text) {
        var $body = $('#body');
        if ($body.length && typeof $body.summernote === 'function' && $body.next('.note-editor').length) {
            $body.summernote('insertText', text);
            return true;
        }
        if ($body.length) {
            $body.val((($body.val() || '') + '\n' + text + '\n').replace(/^\n/, ''));
            return true;
        }
        return false;
    }

    function requestRow(r) {
        var status = r.status || '';
        var badge = status === 'submitted' ? 'success' : (status === 'pending' ? 'warning' : (status === 'read' ? 'default' : 'danger'));
        var need = r.need_label || r.need || '';
        var $el = $('<div class="securehandoff-request">').attr('data-id', r.id || '');
        var $head = $('<div class="securehandoff-request-head">');
        $head.append($('<span>').addClass('label label-' + badge).text(status));
        $head.append($('<span class="securehandoff-need">').text(need));
        $el.append($head);
        if (r.expires_at) {
            var d = new Date(r.expires_at * 1000);
            $el.append($('<div class="text-muted small">').text('Expires ' + d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'));
        }
        if (r.url && status === 'pending') {
            var $row = $('<div class="securehandoff-url-row">');
            $row.append($('<input type="text" class="form-control input-sm securehandoff-url" readonly>').val(r.url));
            $row.append($('<button type="button" class="btn btn-default btn-xs securehandoff-copy">Copy</button>').attr('data-copy', r.url));
            $row.append($('<button type="button" class="btn btn-default btn-xs securehandoff-insert">Insert into reply</button>').attr('data-copy', r.url));
            $el.append($row);
        }
        return $el;
    }

    $(document).on('click', '.securehandoff-copy', function (e) {
        e.preventDefault();
        copyText($(this).attr('data-copy'), $(this));
    });

    $(document).on('click', '.securehandoff-insert', function (e) {
        e.preventDefault();
        var url = $(this).attr('data-copy');
        if (!insertReply(url)) {
            copyText(url, $(this));
        }
    });

    $(document).on('submit', '#securehandoff-mint-form', function (e) {
        e.preventDefault();
        var $form = $(this);
        var $btn = $('#securehandoff-mint-btn');
        var $msg = $('#securehandoff-form-msg');
        $btn.prop('disabled', true);
        $.ajax({
            url: $form.data('url'),
            method: 'POST',
            data: $form.serialize(),
            headers: { 'X-CSRF-TOKEN': csrf() }
        }).done(function (res) {
            if (res.status === 'success' && res.request) {
                flash($msg, 'success', res.msg || 'Link minted.');
                $('.securehandoff-empty').remove();
                $('#securehandoff-requests').prepend(requestRow(res.request));
                $form.find('[name=failed_path],[name=bug_ref]').val('');
            } else {
                flash($msg, 'danger', res.msg || 'Could not mint the link.');
            }
        }).fail(function (xhr) {
            var msg = 'Could not mint the link.';
            if (xhr.responseJSON && xhr.responseJSON.msg) msg = xhr.responseJSON.msg;
            flash($msg, 'danger', msg);
        }).always(function () {
            $btn.prop('disabled', false);
        });
    });

    $(document).on('click', '#securehandoff-test', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var $out = $('#securehandoff-test-result');
        $btn.prop('disabled', true);
        $.ajax({
            url: $btn.data('url'),
            method: 'POST',
            data: { _token: csrf() },
            headers: { 'X-CSRF-TOKEN': csrf() }
        }).done(function (res) {
            flash($out, res.status === 'success' ? 'success' : 'danger', res.msg || '');
        }).fail(function (xhr) {
            var msg = 'Connection failed.';
            if (xhr.responseJSON && xhr.responseJSON.msg) msg = xhr.responseJSON.msg;
            flash($out, 'danger', msg);
        }).always(function () {
            $btn.prop('disabled', false);
        });
    });
})(jQuery);
