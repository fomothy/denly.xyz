// Progressive enhancement only. Everything here has a working fallback: the
// install command is selectable text, and the waitlist form is a real form
// that posts and redirects on its own when this file never runs.

/* ------------------------------------------------ copy the install line ---- */

document.querySelectorAll("[data-copy]").forEach(function (button) {
  var target = document.querySelector(button.dataset.copy);
  var label = button.querySelector(".copy-label");
  if (!target || !label) return;

  var original = label.textContent;
  var revert;

  function show(text, done) {
    label.textContent = text;
    button.classList.toggle("done", done);
    clearTimeout(revert);
    revert = setTimeout(function () {
      label.textContent = original;
      button.classList.remove("done");
    }, 1600);
  }

  button.addEventListener("click", function () {
    // Unavailable on insecure origins and in older browsers. There is no
    // useful fallback, so fail quietly rather than throwing an error into the
    // console of someone just reading a page.
    if (!navigator.clipboard) return;

    navigator.clipboard.writeText(target.textContent.trim()).then(
      function () {
        show("copied", true);
      },
      function () {
        show("press ⌘C", false);
      }
    );
  });
});

/* -------------------------------------------------------- waitlist form ---- */

(function () {
  var form = document.querySelector(".form");
  var status = document.getElementById("form-status");
  if (!form || !status) return;

  var input = form.querySelector('input[name="email"]');
  var honeypot = form.querySelector('input[name="hp_check"]');
  var button = form.querySelector('button[type="submit"]');
  if (!input || !button) return;

  var buttonText = button.textContent;
  var restingNote = status.textContent;

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    // Let the browser's own validation message handle empty or malformed
    // input rather than inventing a second, inconsistent one.
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
          status.textContent = result.body.message;
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
      status.textContent = restingNote;
    }
  }
})();
