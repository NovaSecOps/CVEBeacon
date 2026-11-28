"use strict";

// Optional bulk selection for product and report-mark checkboxes. The form and
// its server-side actions work without this file; the controls are hidden until
// the script runs.
(function () {
    function pickBoxes(form) {
        return Array.prototype.slice.call(
            form.querySelectorAll('input[type="checkbox"][name="pick"]')
        );
    }

    function inClosedGroup(box) {
        var group = box.closest("details.product-group");
        return Boolean(group) && !group.open;
    }

    function hiddenByLayout(box) {
        if (box.hidden || box.getClientRects().length === 0) return true;
        var style = window.getComputedStyle(box);
        return style.display === "none" || style.visibility === "hidden";
    }

    function selectableBoxes(form) {
        return pickBoxes(form).filter(function (box) {
            return !box.matches(":disabled") && !inClosedGroup(box) && !hiddenByLayout(box);
        });
    }

    function checkedBoxes(form) {
        return pickBoxes(form).filter(function (box) {
            return !box.matches(":disabled") && box.checked;
        });
    }

    function setup(form) {
        var selectAll = form.querySelector("[data-bulk-select-all]");
        var clear = form.querySelector("[data-bulk-clear]");
        var count = form.querySelector("[data-bulk-count]");
        var controls = form.querySelector("[data-bulk-controls]");
        if (!selectAll && !clear && !count) return;

        function update() {
            if (!count) return;
            count.textContent = checkedBoxes(form).length + " selected";
        }

        if (selectAll) {
            selectAll.addEventListener("click", function () {
                selectableBoxes(form).forEach(function (box) {
                    box.checked = true;
                });
                update();
            });
        }
        if (clear) {
            clear.addEventListener("click", function () {
                selectableBoxes(form).forEach(function (box) {
                    box.checked = false;
                });
                update();
            });
        }
        form.addEventListener("change", function (event) {
            if (event.target && event.target.name === "pick") update();
        });
        if (controls) controls.setAttribute("data-bulk-ready", "true");
        update();
        form.dataset.bulkReady = "true";
    }

    // Open the product group that contains a #product-<asset_id> target, then
    // bring the row into view. Other groups keep their default state.
    function revealProductAnchor() {
        var hash = window.location.hash;
        if (hash.indexOf("#product-") !== 0) return;
        var id = hash.slice(1);
        try {
            id = decodeURIComponent(id);
        } catch (error) {
            return;
        }
        var row = document.getElementById(id);
        if (!row) return;
        var group = row.closest("details.product-group");
        if (group && !group.open) group.open = true;
        if (typeof row.scrollIntoView === "function") row.scrollIntoView({block: "center"});
    }

    // Below the desktop breakpoint the filter card starts collapsed unless a
    // filter is active. Without this file it stays open, so the fields remain
    // reachable.
    function setupFilterPanel() {
        var panel = document.querySelector("details[data-filter-panel]");
        if (!panel || panel.hasAttribute("data-active-filters")) return;
        if (window.matchMedia && window.matchMedia("(max-width: 900px)").matches) {
            panel.open = false;
        }
    }

    document.addEventListener("DOMContentLoaded", function () {
        setupFilterPanel();
        Array.prototype.forEach.call(document.querySelectorAll("form[data-bulk-form]"), setup);
        revealProductAnchor();
    });
    window.addEventListener("hashchange", revealProductAnchor);
})();
