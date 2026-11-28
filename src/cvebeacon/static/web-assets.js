"use strict";

// Optional bulk selection for product and report-mark checkboxes. The form and
// its server-side actions work without this file; the controls are hidden until
// the script runs.
(function () {
    function visibleEnabledCheckboxes(form) {
        return Array.prototype.filter.call(
            form.querySelectorAll('input[type="checkbox"][name="pick"]'),
            function (box) {
                return !box.disabled && box.offsetParent !== null;
            }
        );
    }

    function setup(form) {
        var selectAll = form.querySelector("[data-bulk-select-all]");
        var clear = form.querySelector("[data-bulk-clear]");
        var count = form.querySelector("[data-bulk-count]");
        var controls = form.querySelector("[data-bulk-controls]");
        if (!selectAll && !clear && !count) return;

        function update() {
            if (!count) return;
            var selected = visibleEnabledCheckboxes(form).filter(function (box) {
                return box.checked;
            }).length;
            count.textContent = selected + " selected";
        }

        if (selectAll) {
            selectAll.addEventListener("click", function () {
                visibleEnabledCheckboxes(form).forEach(function (box) {
                    box.checked = true;
                });
                update();
            });
        }
        if (clear) {
            clear.addEventListener("click", function () {
                visibleEnabledCheckboxes(form).forEach(function (box) {
                    box.checked = false;
                });
                update();
            });
        }
        form.addEventListener("change", function (event) {
            if (event.target && event.target.name === "pick") update();
        });
        update();
        if (controls) controls.setAttribute("data-bulk-ready", "true");
    }

    document.addEventListener("DOMContentLoaded", function () {
        Array.prototype.forEach.call(document.querySelectorAll("form[data-bulk-form]"), setup);
    });
})();
