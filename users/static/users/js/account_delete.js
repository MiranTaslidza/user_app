document.addEventListener('DOMContentLoaded', function () {
    const inputs = Array.from(
        document.querySelectorAll('.deletion-code-input')
    );
    const deleteButton = document.getElementById('delete-account-button');

    if (!inputs.length || !deleteButton) {
        return;
    }

    // Dugme prikazujemo tek kada svih šest polja sadrže cifru.
    function updateButton() {
        deleteButton.hidden = !inputs.every(
            input => /^[0-9]$/.test(input.value)
        );
    }

    // Raspoređujemo zalijepljeni ili automatski popunjeni kod.
    function fillDigits(value, startIndex) {
        const digits = value.replace(/[^0-9]/g, '');

        if (!digits) {
            return;
        }

        // Cijeli šestocifreni kod uvijek popunjava sva polja.
        const start = digits.length >= inputs.length ? 0 : startIndex;
        const available = inputs.length - start;
        const characters = digits.slice(0, available).split('');

        characters.forEach(function (digit, offset) {
            inputs[start + offset].value = digit;
        });

        const nextIndex = Math.min(
            start + characters.length,
            inputs.length - 1
        );

        inputs[nextIndex].focus();
        inputs[nextIndex].select();
        updateButton();
    }

    inputs.forEach(function (input, index) {
        input.addEventListener('input', function () {
            const digits = input.value.replace(/[^0-9]/g, '');

            if (digits.length > 1) {
                fillDigits(digits, index);
                return;
            }

            input.value = digits;

            if (digits && index < inputs.length - 1) {
                inputs[index + 1].focus();
                inputs[index + 1].select();
            }

            updateButton();
        });

        input.addEventListener('paste', function (event) {
            event.preventDefault();
            fillDigits(event.clipboardData.getData('text'), index);
        });

        input.addEventListener('keydown', function (event) {
            if (event.key === 'Backspace' && !input.value && index > 0) {
                inputs[index - 1].focus();
                inputs[index - 1].select();
            }

            if (event.key === 'ArrowLeft' && index > 0) {
                event.preventDefault();
                inputs[index - 1].focus();
            }

            if (event.key === 'ArrowRight' && index < inputs.length - 1) {
                event.preventDefault();
                inputs[index + 1].focus();
            }
        });

        input.addEventListener('focus', function () {
            input.select();
        });
    });

    updateButton();
});
