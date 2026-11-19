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

const mode = document.querySelector('select[name="mode"]');
if (mode) {
    const every = mode.form.elements.namedItem("every");
    const times = mode.form.elements.namedItem("times");
    const update = () => {
        const fixed = mode.value === "times";
        every.required = !fixed;
        times.required = fixed;
    };
    mode.addEventListener("change", update);
    update();
}
