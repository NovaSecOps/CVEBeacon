"use strict";

// Progressive enhancement for the dashboard. Every page works without this
// script: it adds a theme toggle, a collapsible mobile menu and optional
// confirmation prompts.

(function () {
    var root = document.documentElement;
    var KEY = "cvebeacon-theme";

    // Browser storage can be blocked or throw; never depend on it.
    function readTheme() {
        try {
            var value = window.localStorage.getItem(KEY);
            return value === "light" || value === "dark" ? value : null;
        } catch (error) {
            return null;
        }
    }

    function saveTheme(value) {
        try {
            window.localStorage.setItem(KEY, value);
        } catch (error) {
            // The choice then applies to this page view only.
        }
    }

    function systemTheme() {
        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    function currentTheme() {
        return root.getAttribute("data-theme") || systemTheme();
    }

    // Runs while the page head loads, so the saved theme shows without a flash.
    root.classList.add("js");
    var saved = readTheme();
    if (saved) root.setAttribute("data-theme", saved);

    function syncToggle(button) {
        var theme = currentTheme();
        button.setAttribute("data-mode", theme);
        var label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
        button.setAttribute("aria-label", label);
        button.setAttribute("title", label);
    }

    document.addEventListener("DOMContentLoaded", function () {
        var themeButton = document.querySelector(".theme-toggle");
        if (themeButton) {
            syncToggle(themeButton);
            themeButton.addEventListener("click", function () {
                var next = currentTheme() === "dark" ? "light" : "dark";
                root.setAttribute("data-theme", next);
                saveTheme(next);
                syncToggle(themeButton);
            });
            if (window.matchMedia) {
                var query = window.matchMedia("(prefers-color-scheme: dark)");
                var follow = function () { syncToggle(themeButton); };
                if (query.addEventListener) query.addEventListener("change", follow);
            }
        }

        var menuButton = document.querySelector(".nav-toggle");
        if (menuButton) {
            var setOpen = function (open) {
                if (open) root.setAttribute("data-nav", "open");
                else root.removeAttribute("data-nav");
                menuButton.setAttribute("aria-expanded", open ? "true" : "false");
            };
            menuButton.addEventListener("click", function () {
                setOpen(menuButton.getAttribute("aria-expanded") !== "true");
            });
            document.addEventListener("keydown", function (event) {
                if (event.key === "Escape" && menuButton.getAttribute("aria-expanded") === "true") {
                    setOpen(false);
                    menuButton.focus();
                }
            });
        }

        // The section tabs scroll in one row on narrow screens. Keep the
        // current page visible without scrolling the page itself.
        var tabs = document.querySelector(".section-tabs");
        var currentTab = tabs && tabs.querySelector('[aria-current="page"]');
        if (currentTab) {
            var left = currentTab.offsetLeft;
            var right = left + currentTab.offsetWidth;
            if (left < tabs.scrollLeft) tabs.scrollLeft = left;
            else if (right > tabs.scrollLeft + tabs.clientWidth) {
                tabs.scrollLeft = right - tabs.clientWidth;
            }
        }
    });

    // Optional confirmation: <form data-confirm="..."> or <button data-confirm="...">.
    document.addEventListener("submit", function (event) {
        var form = event.target;
        var source = event.submitter && event.submitter.getAttribute("data-confirm") ? event.submitter : form;
        var message = source.getAttribute && source.getAttribute("data-confirm");
        if (message && !window.confirm(message)) event.preventDefault();
    });
})();
