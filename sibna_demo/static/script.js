document.addEventListener('DOMContentLoaded', () => {
    const fetchVersion = async () => {
        const res = await fetch('/api/version');
        const data = await res.json();
        document.getElementById('version-tag').textContent = `v${data.sdk_version}`;
    };
    fetchVersion();

    document.getElementById('btn-generate-identity').onclick = async () => {
        const res = await fetch('/api/generate_identity', { method: 'POST' });
        const data = await res.json();
        const el = document.getElementById('display-pubkey');
        el.textContent = data.public_key;
        el.classList.remove('hidden');
    };

    document.getElementById('btn-encrypt').onclick = async () => {
        const plaintext = document.getElementById('plaintext-input').value;
        const res = await fetch('/api/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ plaintext })
        });
        const data = await res.json();
        document.getElementById('display-ciphertext').textContent = data.ciphertext;
        document.getElementById('display-key').textContent = data.key;
        document.getElementById('crypto-info').classList.remove('hidden');
    };
});
