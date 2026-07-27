// Progressive enhancement only. The waitlist form is a real form that posts
// and redirects to /thanks on its own when this file never runs, so a blocked
// or failed script costs a visitor nothing.

(function () {
  var form = document.querySelector(".waitlist-form");
  var status = document.getElementById("form-status");
  if (!form || !status) return;

  var input = form.querySelector('input[name="email"]');
  var honeypot = form.querySelector('input[name="hp_check"]');
  var button = form.querySelector('button[type="submit"]');
  if (!input || !button) return;

  var buttonText = button.textContent;
  // Snapshot of our own static markup, taken before anything is written to the
  // page — the resting note contains a link to the repo. It is only ever
  // restored verbatim, and no user input or server response reaches it: every
  // message from the function is written with textContent below. Do not put
  // anything dynamic through this variable.
  var restingNote = status.innerHTML;

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    // Let the browser's own validation bubble handle empty or malformed input
    // rather than inventing a second, inconsistent message.
    if (!form.reportValidity()) return;

    setBusy(true);
    status.classList.remove("is-error", "is-success");
    status.textContent = "Adding you…";

    fetch(form.action, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        email: input.value,
        hp_check: honeypot ? honeypot.value : "",
      }),
    })
      .then(function (response) {
        return response.json().then(function (body) {
          return { ok: response.ok, body: body };
        });
      })
      .then(function (result) {
        if (result.ok) {
          form.hidden = true;
          status.classList.add("is-success");
          status.textContent = "🦊 " + result.body.message;
        } else {
          setBusy(false);
          status.classList.add("is-error");
          status.textContent = result.body.message || "That didn't work. Try again.";
        }
      })
      .catch(function () {
        setBusy(false);
        status.classList.add("is-error");
        status.textContent = "Could not reach the server. Try again shortly.";
      });
  });

  function setBusy(busy) {
    button.disabled = busy;
    input.disabled = busy;
    button.textContent = busy ? "Joining…" : buttonText;
    if (!busy && status.textContent === "Adding you…") {
      status.innerHTML = restingNote;
    }
  }
})();
