<?php

namespace Modules\SecureHandoff\Http\Controllers;

use App\Conversation;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Modules\SecureHandoff\Client;

class SecureHandoffController extends Controller
{
    /**
     * Mint a customer link via the handoff staff API. ticket_id is the
     * conversation id so FreeScout note write-back lands on this ticket.
     */
    public function mint(Request $request, $conversation)
    {
        $conversation = $this->conversationForUser($conversation);

        $need = (string) $request->input('need', '');
        $failed = trim((string) $request->input('failed_path', ''));
        $bug = trim((string) $request->input('bug_ref', ''));
        $ttl = (int) $request->input('ttl', 172800);

        if ($need === '' || $failed === '' || $bug === '') {
            return response()->json([
                'status' => 'error',
                'msg'    => __('Need, failed product path, and bug reference are all required.'),
            ]);
        }

        $result = Client::request('POST', '/api/v1/requests', [
            'ticket_id'    => (string) $conversation->id,
            'need'         => $need,
            'failed_path'  => $failed,
            'bug_ref'      => $bug,
            'ttl'          => $ttl,
        ]);

        if (!$result['ok']) {
            return response()->json([
                'status' => 'error',
                'msg'    => $result['error'] ?: __('Handoff refused the request.'),
            ]);
        }

        $data = $result['body']['data'] ?? [];

        return response()->json([
            'status'  => 'success',
            'msg'     => __('Link minted. Send it to the customer — do not paste credentials into this ticket.'),
            'request' => $data,
        ]);
    }

    /**
     * Settings-page connection check. Admin only.
     */
    public function test()
    {
        $user = auth()->user();
        if (!$user || !$user->isAdmin()) {
            abort(403);
        }

        $me = Client::request('GET', '/api/v1/me');
        if (!$me['ok']) {
            return response()->json([
                'status' => 'error',
                'msg'    => $me['error'] ?: __('Could not authenticate to the handoff app.'),
            ]);
        }

        $email = $me['body']['data']['email'] ?? '';

        return response()->json([
            'status' => 'success',
            'msg'    => $email !== ''
                ? __('Connected as :email', ['email' => $email])
                : __('Connected.'),
        ]);
    }

    /**
     * @param int|string $id
     * @return Conversation
     */
    protected function conversationForUser($id)
    {
        $conversation = Conversation::findOrFail($id);
        $user = auth()->user();
        if (!$user || !$user->hasAccessToMailbox($conversation->mailbox_id)) {
            abort(403);
        }
        return $conversation;
    }
}
