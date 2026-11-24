"use strict";

// Comfort only: the server is the only translator of criteria into a
// condition.  Without this file every row is visible and submitted, and unused
// rows are ignored by dashboard_rule_builder.py.
for (const fieldset of document.querySelectorAll("fieldset.criteria")) {
    const table = fieldset.querySelector("table.criteria-table");
    if (!table) {
        continue;
    }
    const rows = Array.from(table.querySelectorAll("tr.criterion"));
    for (const row of rows) {
        const use = row.querySelector("[data-rule-use]");
        const value = row.querySelector("[data-rule-value]");
        if (!use || !value || use.disabled || value.disabled) {
            continue;
        }
        const sync = () => {
            const unused = use.value === "";
            value.disabled = unused;
            row.classList.toggle("criterion-unused", unused);
        };
        use.addEventListener("change", sync);
        sync();
    }
    const used = rows.filter((row) => {
        const use = row.querySelector("[data-rule-use]");
        return use && use.value !== "";
    });
    const unused = rows.filter((row) => !used.includes(row));
    if (used.length >= 3 && unused.length > 0) {
        const details = document.createElement("details");
        details.className = "disclosure criteria-more";
        const summary = document.createElement("summary");
        summary.textContent = "More criteria";
        details.appendChild(summary);
        const more = document.createElement("table");
        more.className = "criteria-table";
        const body = document.createElement("tbody");
        for (const row of unused) {
            body.appendChild(row);
        }
        more.appendChild(body);
        details.appendChild(more);
        table.after(details);
    }
}
