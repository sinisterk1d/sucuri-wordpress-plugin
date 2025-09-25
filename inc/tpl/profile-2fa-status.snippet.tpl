<div class="sucuriscan-profile-2fa-status" data-ajax-url="%%SUCURI.ajax_url%%" data-ajax-nonce="%%SUCURI.ajax_nonce%%"
    data-user-id="%%SUCURI.user_id%%">

    <p class="sucuriscan-mb-5" data-cy="sucuriscan-2fa-status-text">
        <span class="dashicons dashicons-yes sucuriscan-2fa-status-icon" aria-hidden="true"
            style="color:#46b450"></span>
        Two-Factor Authentication is enabled for this account.
    </p>

    <p class="sucuriscan-2fa-reset-row">
        <button type="button" class="button button-secondary" id="sucuri-2fa-reset-btn"
            aria-controls="sucuri-2fa-reset-msg" data-cy="sucuriscan-2fa-reset-btn">
            Reset two-factor
        </button>
        <span id="sucuri-2fa-reset-msg" class="sucuriscan-2fa-reset-msg" role="status" aria-live="polite"
            style="margin-left:8px;">
        </span>
    </p>
</div>

<script type="text/javascript">
    (function sucuriscanProfile2FAStatus() {
        var root = document.querySelector('.sucuriscan-profile-2fa-status');
        if (!root) return;

        var ajaxUrl = root.getAttribute('data-ajax-url') || '%%SUCURI.ajax_url%%';
        var ajaxNonce = root.getAttribute('data-ajax-nonce') || '%%SUCURI.ajax_nonce%%';
        var userId = root.getAttribute('data-user-id') || '%%SUCURI.user_id%%';

        var btn = root.querySelector('#sucuri-2fa-reset-btn');
        var msg = root.querySelector('#sucuri-2fa-reset-msg');

        function setMessage(text, type) {
            if (!msg) return;
            msg.textContent = text || '';
            msg.classList.remove('sucuriscan-text-error', 'sucuriscan-text-success');
            if (type === 'error') msg.classList.add('sucuriscan-text-error');
            if (type === 'success') msg.classList.add('sucuriscan-text-success');
        }

        function setBusy(isBusy) {
            if (!btn) return;
            btn.disabled = !!isBusy;
            btn.setAttribute('aria-disabled', isBusy ? 'true' : 'false');
        }

        function hydrateSetup(container) {
            if (!container) return;

            try {
                var qrEl = container.querySelector('#sucuriscan-topt-qr');
                if (qrEl && typeof qrcode === 'function') {
                    var uri = qrEl.getAttribute('data-otpauth') || '';
                    var qr = qrcode(0, 'M');
                    qr.addData(uri);
                    qr.make();
                    qrEl.innerHTML = qr.createImgTag(6, 4);
                }
            } catch (e) { }

            var enableBtn = container.querySelector('#sucuri-2fa-enable-btn');
            var enableMsg = container.querySelector('#sucuri-2fa-enable-msg');

            function setEnableMsg(text, type) {
                if (!enableMsg) return;
                enableMsg.textContent = text || '';
                enableMsg.classList.remove('sucuriscan-text-error', 'sucuriscan-text-success');
                if (type === 'error') enableMsg.classList.add('sucuriscan-text-error');
                if (type === 'success') enableMsg.classList.add('sucuriscan-text-success');
            }

            if (enableBtn) {
                enableBtn.addEventListener('click', function () {
                    var setupRoot = container.querySelector('.sucuriscan-profile-2fa-setup') || container;
                    var setupAjaxUrl = setupRoot.getAttribute('data-ajax-url') || ajaxUrl;
                    var setupAjaxNonce = setupRoot.getAttribute('data-ajax-nonce') || ajaxNonce;
                    var setupUserId = setupRoot.getAttribute('data-user-id') || userId;

                    var codeEl = container.querySelector('#sucuriscan-totp-code');
                    var secretEl = container.querySelector('input[name="sucuri_2fa_secret"]');

                    var code = codeEl ? String(codeEl.value || '').replace(/\s+/g, '') : '';
                    var secret = secretEl ? String(secretEl.value || '') : '';

                    if (!/^\d{6}$/.test(code)) {
                        setEnableMsg('Enter six digits', 'error');
                        return;
                    }

                    setEnableMsg('Verifying…');

                    var params = new URLSearchParams();
                    params.append('action', 'sucuri_profile_2fa_enable');
                    params.append('nonce', setupAjaxNonce);
                    params.append('user_id', setupUserId);
                    params.append('code', code);
                    params.append('secret', secret);

                    fetch(setupAjaxUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                        body: params.toString()
                    })
                        .then(function (r) { return r.json().catch(function () { return {}; }); })
                        .then(function (resp) {
                            if (resp && resp.success && resp.data && resp.data.html) {
                                var cell = container.closest('td') || container;
                                cell.innerHTML = resp.data.html;
                                setEnableMsg('', '');
                            } else {
                                var err = (resp && resp.data && (resp.data.message || resp.data.error)) || 'Verification failed';
                                setEnableMsg(err, 'error');
                            }
                        })
                        .catch(function () {
                            setEnableMsg('Verification failed', 'error');
                        });
                });
            }
        }

        if (!btn) return;
        btn.addEventListener('click', function () {
            if (!window.confirm('This will disable two-factor for this user. Continue?')) return;

            setBusy(true);
            setMessage('Resetting…');

            var params = new URLSearchParams();
            params.append('action', 'sucuri_profile_2fa_reset');
            params.append('nonce', ajaxNonce);
            params.append('user_id', userId);

            fetch(ajaxUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: params.toString()
            })
                .then(function (r) { return r.json().catch(function () { return {}; }); })
                .then(function (resp) {
                    if (resp && resp.success && resp.data && resp.data.html) {
                        var cell = root.closest('td') || root;
                        cell.innerHTML = resp.data.html;
                        hydrateSetup(cell);
                    } else {
                        var err = (resp && resp.data && (resp.data.message || resp.data.error)) || 'Reset failed';
                        setMessage(err, 'error');
                        setBusy(false);
                    }
                })
                .catch(function () {
                    setMessage('Reset failed', 'error');
                    setBusy(false);
                });
        });
    })();
</script>