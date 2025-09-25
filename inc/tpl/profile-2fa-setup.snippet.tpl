<div class="sucuriscan-profile-2fa-setup" data-ajax-url="%%SUCURI.ajax_url%%" data-ajax-nonce="%%SUCURI.ajax_nonce%%"
    data-user-id="%%SUCURI.user_id%%">

    <p>Two-Factor Authentication is not activated for your account. Scan the QR code below or enter the key manually in
        your authenticator app, then enter the 6-digit code to enable it.</p>

    <div class="sucuriscan-2fa-setup-row">
        <div id="sucuriscan-topt-qr" class="sucuriscan-topt-qr" data-otpauth="%%SUCURI.topt_url%%"></div>

        <div class="sucuriscan-2fa-setup-form" role="form" aria-labelledby="sucuriscan-2fa-setup-label">
            <p id="sucuriscan-2fa-setup-label">
                <strong>Secret:</strong>
                <code>%%SUCURI.totp_key%%</code>
            </p>

            <label for="sucuriscan-totp-code"><strong>Verification code</strong></label><br />
            <input type="text" id="sucuriscan-totp-code" name="sucuriscan_totp_code" maxlength="6" inputmode="numeric"
                pattern="[0-9]{6}" placeholder="123456" autocomplete="one-time-code" class="regular-text"
                aria-describedby="sucuriscan-2fa-enable-msg" />

            <input type="hidden" name="sucuri_2fa_secret" value="%%SUCURI.totp_key%%" />

            <div class="sucuriscan-2fa-action-row">
                <button type="button" class="button button-primary" id="sucuri-2fa-enable-btn">
                    Verify & Enable
                </button>
                <span id="sucuri-2fa-enable-msg" class="sucuriscan-2fa-enable-msg" role="status"
                    aria-live="polite"></span>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript">
    (function renderQr() {
        if (typeof qrcode !== 'function') return;

        var el = document.getElementById('sucuriscan-topt-qr');

        if (!el) return;

        try {
            var uri = el.getAttribute('data-otpauth') || '';
            var qr = qrcode(0, 'M');
            qr.addData(uri);
            qr.make();
            el.innerHTML = qr.createImgTag(6, 4);
        } catch (e) { }
    })();

    (function enable2FA() {
        var root = document.querySelector('.sucuriscan-profile-2fa-setup');
        if (!root) return;

        var ajaxUrl = root.getAttribute('data-ajax-url') || '';
        var ajaxNonce = root.getAttribute('data-ajax-nonce') || '';
        var userId = root.getAttribute('data-user-id') || '';

        var btn = document.getElementById('sucuri-2fa-enable-btn');
        var msg = document.getElementById('sucuri-2fa-enable-msg');

        function setMessage(text, type) {
            if (!msg) return;
            msg.textContent = text || '';
            msg.classList.remove('sucuriscan-text-error', 'sucuriscan-text-success');
            if (type === 'error') msg.classList.add('sucuriscan-text-error');
            if (type === 'success') msg.classList.add('sucuriscan-text-success');
        }

        if (!btn) return;
        btn.addEventListener('click', function () {
            var codeEl = document.getElementById('sucuriscan-totp-code');
            var secretEl = root.querySelector('input[name="sucuri_2fa_secret"]');

            var code = codeEl ? String(codeEl.value || '').replace(/\s+/g, '') : '';
            var secret = secretEl ? String(secretEl.value || '') : '';

            if (!/^\d{6}$/.test(code)) {
                setMessage('Enter six digits', 'error');
                return;
            }

            setMessage('Verifying…');

            var params = new URLSearchParams();
            params.append('action', 'sucuri_profile_2fa_enable');
            params.append('nonce', ajaxNonce);
            params.append('user_id', userId);
            params.append('code', code);
            params.append('secret', secret);

            fetch(ajaxUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: params.toString()
            })
                .then(function (r) { return r.json().catch(function () { return {}; }); })
                .then(function (resp) {
                    if (resp && resp.success && resp.data && resp.data.html) {
                        var container = btn.closest('td') || root;
                        container.innerHTML = resp.data.html;
                        setMessage('', '');
                    } else {
                        var err = (resp && resp.data && (resp.data.message || resp.data.error)) || 'Verification failed';
                        setMessage(err, 'error');
                    }
                })
                .catch(function () {
                    setMessage('Verification failed', 'error');
                });
        });
    })();
</script>