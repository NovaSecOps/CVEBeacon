"use strict";

// Keep the submitted value explicit, including an unchecked false value.
// Untouched fields retain omission and therefore retain loader defaults.
for (const checkbox of document.querySelectorAll("[data-boolean]")) {
    checkbox.addEventListener("change", () => {
        checkbox.form.elements.namedItem(checkbox.dataset.boolean).value = String(checkbox.checked);
    });
}
