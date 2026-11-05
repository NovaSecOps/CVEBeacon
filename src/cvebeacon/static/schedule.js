"use strict";

const loggedOut = document.querySelector('input[name="run_logged_out"]');
if (loggedOut) {
    const update = () => {
        for (const name of ["account", "password"]) {
            const field = loggedOut.form.elements.namedItem(name);
            field.disabled = !loggedOut.checked;
            if (field.disabled) field.value = "";
        }
    };
    loggedOut.addEventListener("change", update);
    update();
}
