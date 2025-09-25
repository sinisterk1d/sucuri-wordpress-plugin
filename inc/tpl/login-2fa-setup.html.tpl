<div style="text-align:center;margin:12px 0;">
    <strong>{{Sucuri Security}}</strong>
</div>

<div style="text-align:center;">
    <div id="sucuriscan-totp-qr"
        style="display:inline-block;background:#fff;padding:8px;border:1px solid #ddd;min-width:240px;min-height:240px;">
    </div>
    <p style="margin-top:10px;">{{Secret (manual entry):}} <code>%%SUCURI.SecretManual%%</code></p>
</div>

<form name="sucuri-2fa-setup" id="loginform" action="%%SUCURI.ActionURL%%" method="post">
    %%%SUCURI.NonceField%%%
    <p style="display:block;">
        <label for="sucuriscan-totp-code">{{Enter code}}<br />
            <input type="text" name="sucuriscan_totp_code" id="sucuriscan-totp-code" class="input" maxlength="6"
                pattern="[0-9]{6}" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"
                style="display:block;" />
        </label>
    </p>
    <p class="submit" style="display:block;">
        <input type="submit" name="wp-submit" id="sucuriscan-totp-submit" class="button button-primary button-large"
            value="{{Activate and continue}}" style="display:block;" />
    </p>
</form>

<script src="%%SUCURI.PluginURL%%/inc/js/qr.js"></script>
<script>
    (function () {
        try {
            var uri = '%%SUCURI.OtpauthURI%%';
            var el = document.getElementById('sucuriscan-totp-qr');
            if (el && window.qrcode) {
                var qr = qrcode(0, 'M');
                qr.addData(uri);
                qr.make();
                el.innerHTML = qr.createImgTag(6, 4);
            }
        } catch (e) { }
    })();
</script>