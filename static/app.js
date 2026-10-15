/* Northstar client behaviour: password toggles, live parking grids, the space
   detail panel and the admin ticket list. */
(function () {
  "use strict";

  var POLL_INTERVAL_MS = 5000;
  var STATUS_COLORS = ["green", "yellow", "red"];

  /* ------------------------------------------------------------------ */
  /* Password visibility toggles                                         */
  /* ------------------------------------------------------------------ */
  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      var showing = input.type === "text";
      input.type = showing ? "password" : "text";
      button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      button.title = showing ? "Show password" : "Hide password";
    });
  });

  /* ------------------------------------------------------------------ */
  /* Helpers                                                             */
  /* ------------------------------------------------------------------ */
  function statusLabel(status) {
    return status ? status : "Available";
  }

  function setColorClasses(element, prefix, color) {
    STATUS_COLORS.forEach(function (name) {
      element.classList.remove(prefix + name);
    });
    element.classList.add(prefix + color);
  }

  /* ------------------------------------------------------------------ */
  /* Space detail panel (shared by the admin and customer grids)          */
  /* ------------------------------------------------------------------ */
  var panel = null;

  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement("div");
    panel.className = "space-panel";
    panel.id = "space-panel";
    panel.hidden = true;
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.innerHTML =
      '<div class="space-panel-card">' +
      '  <div class="space-panel-head">' +
      '    <h3 class="space-panel-title" data-panel-title>Space</h3>' +
      '    <button type="button" class="space-panel-close" data-panel-close aria-label="Close space details">&times;</button>' +
      "  </div>" +
      '  <dl>' +
      '    <div class="space-panel-row"><dt>Space ID</dt><dd data-panel-id></dd></div>' +
      '    <div class="space-panel-row"><dt>Name</dt><dd data-panel-name></dd></div>' +
      '    <div class="space-panel-row"><dt>Status</dt><dd><span class="space-status space-status--green" data-panel-status></span></dd></div>' +
      '    <div class="space-panel-row"><dt>Notes</dt><dd data-panel-notes></dd></div>' +
      "  </dl>" +
      '  <div class="space-panel-actions" data-panel-actions hidden>' +
      '    <a class="primary-button" data-panel-link href="#"></a>' +
      "  </div>" +
      "</div>";
    document.body.appendChild(panel);

    panel.querySelector("[data-panel-close]").addEventListener("click", closePanel);
    panel.addEventListener("click", function (event) {
      if (event.target === panel) closePanel();
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !panel.hidden) closePanel();
    });
    return panel;
  }

  function closePanel() {
    if (!panel) return;
    panel.hidden = true;
    delete panel.dataset.spaceId;
  }

  function renderPanel(card) {
    var node = ensurePanel();
    var spaceId = card.dataset.spaceId || "";
    var status = card.dataset.spaceStatus || "";
    var color = card.dataset.spaceColor || "green";
    var notes = card.dataset.spaceNotes || "";

    node.dataset.spaceId = spaceId;
    node.querySelector("[data-panel-title]").textContent =
      "Space " + (card.dataset.spaceName || spaceId);
    node.querySelector("[data-panel-id]").textContent = spaceId;
    node.querySelector("[data-panel-name]").textContent =
      card.dataset.spaceName || "";
    node.querySelector("[data-panel-notes]").textContent = notes || "—";

    var badge = node.querySelector("[data-panel-status]");
    badge.textContent = statusLabel(status);
    setColorClasses(badge, "space-status--", color);

    var actions = node.querySelector("[data-panel-actions]");
    var link = node.querySelector("[data-panel-link]");
    if (card.dataset.spaceUrl) {
      link.textContent = status ? "Open ticket" : "Generate ticket";
      link.setAttribute("href", card.dataset.spaceUrl);
      actions.hidden = false;
    } else {
      actions.hidden = true;
      link.removeAttribute("href");
    }

    node.hidden = false;
  }

  function bindCards(grid) {
    grid.querySelectorAll("[data-space-id]").forEach(function (card) {
      if (card.dataset.panelBound === "true") return;
      card.dataset.panelBound = "true";
      card.addEventListener("click", function () {
        renderPanel(card);
      });
      card.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          renderPanel(card);
        }
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Live grid polling                                                   */
  /* ------------------------------------------------------------------ */
  function applySpacesPayload(grid, payload) {
    if (!payload || !Array.isArray(payload.spaces)) return;
    var byId = {};
    payload.spaces.forEach(function (space) {
      byId[String(space.id)] = space;
    });

    grid.querySelectorAll("[data-space-id]").forEach(function (card) {
      var space = byId[String(card.dataset.spaceId)];
      if (!space) return;
      var status = space.status || "";
      var color = space.color || "green";

      card.dataset.spaceStatus = status;
      card.dataset.spaceColor = color;
      card.dataset.spaceName = space.name || "";
      card.dataset.spaceNotes = space.notes || "";
      setColorClasses(card, "space-card--", color);

      var label = card.querySelector("[data-space-status-label]");
      if (label) {
        label.textContent = statusLabel(status);
        setColorClasses(label, "space-status--", color);
      }
      card.setAttribute(
        "aria-label",
        "Space " + (space.name || space.id) + ", " + statusLabel(status)
      );
    });

    var lot = payload.lot || {};
    if (lot.id !== undefined) {
      var available = document.querySelector('[data-lot-available="' + lot.id + '"]');
      if (available) available.textContent = lot.available_spaces;
      var total = document.querySelector('[data-lot-total="' + lot.id + '"]');
      if (total) total.textContent = lot.total_spaces;
      var openCount = document.querySelector('[data-lot-open="' + lot.id + '"]');
      if (openCount && typeof lot.total_spaces === "number") {
        openCount.textContent = Math.max(lot.total_spaces - lot.available_spaces, 0);
      }
    }

    // Keep an already-open detail panel consistent with the new data, without
    // rebuilding or dismissing it.
    if (panel && !panel.hidden) {
      var current = panel.querySelector("[data-panel-status]");
      var card = grid.querySelector(
        '[data-space-id="' + panel.dataset.spaceId + '"]'
      );
      if (current && card) {
        var liveStatus = card.dataset.spaceStatus || "";
        current.textContent = statusLabel(liveStatus);
        setColorClasses(current, "space-status--", card.dataset.spaceColor || "green");
        var link = panel.querySelector("[data-panel-link]");
        if (link && card.dataset.spaceUrl) {
          link.textContent = liveStatus ? "Open ticket" : "Generate ticket";
        }
      }
    }
  }

  function startGridPolling() {
    document.querySelectorAll("[data-spaces-grid]").forEach(function (grid) {
      if (grid.dataset.polling === "true") return;
      var url = grid.dataset.spacesUrl;
      if (!url) return;
      grid.dataset.polling = "true";
      bindCards(grid);

      var inFlight = false;
      var timer = null;

      function refresh() {
        // Skip overlapping requests and avoid polling a hidden tab.
        if (inFlight || document.hidden) return;
        inFlight = true;
        window
          .fetch(url, {
            headers: { Accept: "application/json" },
            credentials: "same-origin",
          })
          .then(function (response) {
            if (!response.ok) throw new Error("Request failed");
            return response.json();
          })
          .then(function (payload) {
            applySpacesPayload(grid, payload);
          })
          .catch(function () {
            /* Failed polls must never break the page; the next tick retries. */
          })
          .then(function () {
            inFlight = false;
          });
      }

      function start() {
        if (timer !== null) return;
        refresh();
        timer = window.setInterval(refresh, POLL_INTERVAL_MS);
      }

      function stop() {
        if (timer === null) return;
        window.clearInterval(timer);
        timer = null;
      }

      document.addEventListener("visibilitychange", function () {
        if (document.hidden) {
          stop();
        } else {
          start();
        }
      });
      window.addEventListener("pagehide", stop);

      start();
    });
  }

  /* ------------------------------------------------------------------ */
  /* Admin ticket list polling                                           */
  /* ------------------------------------------------------------------ */
  function cell(value) {
    var td = document.createElement("td");
    td.textContent = value === null || value === undefined || value === "" ? "—" : value;
    return td;
  }

  function formatTime(value) {
    if (!value) return "—";
    var parsed = new Date(value);
    if (isNaN(parsed.getTime())) return String(value);
    return parsed.toLocaleString();
  }

  function ticketRow(ticket) {
    var tr = document.createElement("tr");
    tr.dataset.ticketId = ticket.id;

    var ticketCell = document.createElement("td");
    var strong = document.createElement("strong");
    strong.textContent = "#" + ticket.id;
    ticketCell.appendChild(strong);
    tr.appendChild(ticketCell);

    var customer = document.createElement("td");
    var name = document.createElement("span");
    name.className = "cell-stack";
    name.textContent = ticket.customer_name;
    var email = document.createElement("span");
    email.className = "cell-sub";
    email.textContent = ticket.customer_email;
    customer.appendChild(name);
    customer.appendChild(email);
    tr.appendChild(customer);

    tr.appendChild(cell(ticket.lot_name));
    tr.appendChild(cell(ticket.space_name));

    var statusCell = document.createElement("td");
    var badge = document.createElement("span");
    badge.className = "space-status space-status--" + ticket.status_field.color;
    badge.textContent = ticket.status_field.value;
    statusCell.appendChild(badge);
    tr.appendChild(statusCell);

    tr.appendChild(cell(formatTime(ticket.start_time)));
    tr.appendChild(cell(formatTime(ticket.end_time)));
    tr.appendChild(cell(formatTime(ticket.started_at)));
    tr.appendChild(cell(formatTime(ticket.ended_at)));
    return tr;
  }

  function startTicketPolling() {
    var body = document.querySelector("[data-tickets-body]");
    if (!body || body.dataset.polling === "true") return;
    var url = body.dataset.ticketsUrl;
    if (!url) return;
    body.dataset.polling = "true";

    var inFlight = false;
    var timer = null;

    function refresh() {
      if (inFlight || document.hidden) return;
      inFlight = true;
      window
        .fetch(url, {
          headers: { Accept: "application/json" },
          credentials: "same-origin",
        })
        .then(function (response) {
          if (!response.ok) throw new Error("Request failed");
          return response.json();
        })
        .then(function (payload) {
          var tickets = (payload && payload.tickets) || [];
          body.textContent = "";
          tickets.forEach(function (ticket) {
            body.appendChild(ticketRow(ticket));
          });
          var empty = document.querySelector("[data-tickets-empty]");
          if (empty) empty.hidden = tickets.length > 0;
          var table = body.closest("[data-tickets-table]");
          if (table) table.hidden = tickets.length === 0;
        })
        .catch(function () {
          /* Ignore transient failures. */
        })
        .then(function () {
          inFlight = false;
        });
    }

    function start() {
      if (timer !== null) return;
      refresh();
      timer = window.setInterval(refresh, POLL_INTERVAL_MS);
    }

    function stop() {
      if (timer === null) return;
      window.clearInterval(timer);
      timer = null;
    }

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        stop();
      } else {
        start();
      }
    });
    window.addEventListener("pagehide", stop);
    start();
  }

  /* ------------------------------------------------------------------ */
  /* Booking form (Generate ticket) without a full page reload            */
  /* ------------------------------------------------------------------ */
  function feedbackNode(form) {
    var node = form.querySelector("[data-booking-feedback]");
    if (!node) {
      node = document.createElement("div");
      node.className = "notice";
      node.setAttribute("data-booking-feedback", "");
      node.setAttribute("role", "status");
      form.insertBefore(node, form.firstChild);
    }
    return node;
  }

  function showFeedback(form, kind, text) {
    var node = feedbackNode(form);
    node.className = "notice " + (kind === "error" ? "notice-error" : "notice-success");
    node.setAttribute("role", kind === "error" ? "alert" : "status");
    node.textContent = text;
    node.hidden = false;
  }

  function describeErrors(detail) {
    if (!detail) return "We could not generate that ticket. Please try again.";
    if (typeof detail === "string") return detail;
    return Object.keys(detail)
      .map(function (field) {
        return field.replace(/_/g, " ") + ": " + detail[field];
      })
      .join(" ");
  }

  function bindBookingForms() {
    document.querySelectorAll("[data-create-booking]").forEach(function (form) {
      if (form.dataset.bound === "true") return;
      form.dataset.bound = "true";
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var button = form.querySelector('button[type="submit"]');
        var original = button ? button.textContent : "";
        if (button) {
          button.disabled = true;
          button.textContent = "Generating…";
        }
        window
          .fetch(form.getAttribute("action"), {
            method: "POST",
            body: new FormData(form),
            headers: {
              "X-Requested-With": "XMLHttpRequest",
              Accept: "application/json",
            },
            credentials: "same-origin",
          })
          .then(function (response) {
            return response
              .json()
              .catch(function () {
                return {};
              })
              .then(function (payload) {
                return { ok: response.ok, payload: payload };
              });
          })
          .then(function (result) {
            if (result.ok) {
              var booking = (result.payload && result.payload.booking) || {};
              var details =
                "Ticket #" +
                booking.id +
                " · " +
                booking.status +
                " · " +
                booking.start_time +
                " → " +
                booking.end_time;
              showFeedback(
                form,
                "success",
                (result.payload.detail || "Ticket generated.") + " " + details
              );
              var url = form.dataset.spaceUrl;
              if (url) {
                var link = document.createElement("a");
                link.className = "text-link";
                link.href = url;
                link.textContent = " Open this ticket";
                feedbackNode(form).appendChild(link);
              }
              form.querySelectorAll("input:not([type=hidden])").forEach(function (input) {
                input.value = "";
              });
            } else {
              showFeedback(form, "error", describeErrors(result.payload.detail));
            }
          })
          .catch(function () {
            showFeedback(form, "error", "Network error. Please try again.");
          })
          .then(function () {
            if (button) {
              button.disabled = false;
              button.textContent = original;
            }
          });
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Active ticket duration counter                                      */
  /* ------------------------------------------------------------------ */
  function startDurationCounter() {
    var element = document.querySelector("#active-duration[data-started-at]");
    if (!element) return;
    var startedAt = new Date(element.getAttribute("data-started-at"));
    if (isNaN(startedAt.getTime())) return;

    function pad(value) {
      return String(value).padStart(2, "0");
    }

    function tick() {
      var totalSeconds = Math.max(Math.floor((Date.now() - startedAt.getTime()) / 1000), 0);
      var hours = Math.floor(totalSeconds / 3600);
      var minutes = Math.floor((totalSeconds % 3600) / 60);
      var seconds = totalSeconds % 60;
      element.textContent =
        pad(hours) + ":" + pad(minutes) + ":" + pad(seconds) +
        " (since " + startedAt.toLocaleString() + ")";
    }

    tick();
    window.setInterval(tick, 1000);
  }

  /* ------------------------------------------------------------------ */
  /* Confirmation prompts for consequential actions                      */
  /* ------------------------------------------------------------------ */
  function bindConfirmationPrompts() {
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      if (form.dataset.confirmBound === "true") return;
      form.dataset.confirmBound = "true";
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.dataset.confirm)) {
          event.preventDefault();
        }
      });
    });
  }

  function init() {
    startGridPolling();
    startTicketPolling();
    bindBookingForms();
    bindConfirmationPrompts();
    startDurationCounter();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
