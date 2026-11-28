document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-address-formset]').forEach(function (section) {
        const list = section.querySelector('[data-address-list]');
        const template = section.querySelector('[data-address-template]');
        const total = section.querySelector('input[name$="-TOTAL_FORMS"]');
        const maximum = section.querySelector('input[name$="-MAX_NUM_FORMS"]');
        const addButton = section.querySelector('[data-add-address]');
        const status = section.querySelector('[data-address-status]');
        if (!list || !template || !total || !addButton) return;

        function update() {
            const active = Array.from(list.querySelectorAll('[data-address-form]'))
                .filter(card => !card.hidden);
            active.forEach(function (card, index) {
                card.querySelector('[data-address-number]').textContent = index + 1;
            });
            addButton.disabled = Boolean(maximum && maximum.value && Number(total.value) >= Number(maximum.value));
        }

        function initialise(card) {
            const deletion = card.querySelector('input[name$="-DELETE"]');
            const removeButton = card.querySelector('[data-remove-address]');
            if (!deletion || !removeButton) return;
            card.querySelector('[data-delete-control]').hidden = true;
            removeButton.hidden = false;

            function remove() {
                deletion.checked = true;
                // Keep IDs and DELETE in the POST while skipping removed fields.
                card.querySelectorAll('input, select, textarea').forEach(function (input) {
                    if (input !== deletion && input.type !== 'hidden') input.disabled = true;
                });
                card.hidden = true;
                update();
            }
            removeButton.addEventListener('click', function () {
                remove();
                addButton.focus();
                status.textContent = 'Address removed. Save your profile to apply changes.';
            });
            if (deletion.checked) remove();
        }

        list.querySelectorAll('[data-address-form]').forEach(initialise);
        addButton.hidden = false;
        addButton.addEventListener('click', function () {
            const index = Number(total.value);
            list.insertAdjacentHTML('beforeend', template.innerHTML.replace(/__prefix__/g, index));
            total.value = index + 1;
            const card = list.lastElementChild;
            initialise(card);
            update();
            card.querySelector('input:not([type="hidden"]):not([name$="-DELETE"])').focus();
            status.textContent = 'New address added.';
        });
        update();
    });
});
