(function () {
  "use strict";

  /* ==================================================================
   * Boot / auth guard
   * ================================================================== */
  const bootOverlay = document.getElementById("bootOverlay");
  const vaultApp = document.getElementById("vaultApp");

  async function boot() {
    const res = await API.request("/api/me");
    if (res.status !== 200) {
      window.location.href = "/login.html";
      return;
    }
    const username = res.data.user.username;
    document.getElementById("userName").textContent = username;
    document.getElementById("userAvatar").textContent =
      username.charAt(0).toUpperCase();

    bootOverlay.hidden = true;
    vaultApp.hidden = false;

    await Promise.all([loadNotes(), initTimer()]);
  }

  /* ==================================================================
   * Toast helper
   * ================================================================== */
  let toastTimer = null;
  const toast = document.getElementById("toast");
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
  }

  /* ==================================================================
   * Notes
   * ================================================================== */
  let notes = [];
  let activeNoteId = null;

  const notesList = document.getElementById("notesList");
  const newNoteInput = document.getElementById("newNoteInput");
  const addNoteBtn = document.getElementById("addNoteBtn");

  function renderNotes(selectId) {
    notesList.innerHTML = "";
    if (notes.length === 0) {
      const empty = document.createElement("div");
      empty.className = "note-row";
      empty.style.color = "var(--muted)";
      empty.style.cursor = "default";
      empty.textContent = "No notes yet. Add one above.";
      notesList.appendChild(empty);
      return;
    }
    notes.forEach((n) => {
      const row = document.createElement("div");
      row.className = "note-row" + (n.id === activeNoteId ? " active" : "");
      row.dataset.id = n.id;

      const title = document.createElement("span");
      title.className = "note-title" + (n.id === activeNoteId ? " active-note" : "");
      title.textContent = n.title || "Untitled";

      const del = document.createElement("button");
      del.className = "note-del";
      del.textContent = "\u00d7";
      del.title = "Delete note";

      del.addEventListener("click", async (e) => {
        e.stopPropagation();
        const r = await API.request("/api/notes/" + n.id, { method: "DELETE" });
        if (r.status === 200) {
          notes = notes.filter((x) => x.id !== n.id);
          if (activeNoteId === n.id) activeNoteId = null;
          renderNotes();
          showToast("Note deleted.");
        } else {
          showToast(r.data.error || "Could not delete note.");
        }
      });

      row.addEventListener("click", () => selectNote(n.id));

      row.appendChild(title);
      row.appendChild(del);
      notesList.appendChild(row);
    });

    if (selectId) {
      const el = notesList.querySelector('[data-id="' + selectId + '"]');
      if (el) el.scrollIntoView({ block: "nearest" });
    }
  }

  async function loadNotes() {
    const res = await API.request("/api/notes");
    if (res.status === 200) {
      notes = res.data.notes || [];
      renderNotes();
    }
  }

  function selectNote(id) {
    activeNoteId = id;
    renderNotes();
    const note = notes.find((n) => n.id === id);
    showToast("Opened: " + (note ? note.title : "note"));
  }

  async function addNote() {
    const title = newNoteInput.value.trim();
    if (!title) {
      showToast("Enter a title first.");
      return;
    }
    const res = await API.request("/api/notes", {
      method: "POST",
      body: JSON.stringify({ title }),
    });
    if (res.status === 201) {
      notes.unshift(res.data.note);
      activeNoteId = res.data.note.id;
      newNoteInput.value = "";
      renderNotes();
      showToast("Note added.");
    } else {
      showToast(res.data.error || "Could not add note.");
    }
  }

  addNoteBtn.addEventListener("click", addNote);
  newNoteInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addNote();
  });

  /* ==================================================================
   * Pomodoro timer
   * ================================================================== */
  const DURATIONS = {
    focus: 25 * 60,
    short: 5 * 60,
    long: 15 * 60,
  };
  const LABELS = { focus: "Focus", short: "Short Break", long: "Long Break" };

  const RADIUS = 105;
  const CIRC = 2 * Math.PI * RADIUS;

  let mode = "focus";
  let total = DURATIONS.focus;
  let remaining = total;
  let timerId = null;
  let sessionsDone = 0;

  const timeDisplay = document.getElementById("timeDisplay");
  const phaseLabel = document.getElementById("phaseLabel");
  const focusBadge = document.getElementById("focusBadge");
  const progressRing = document.getElementById("progressRing");
  const statusLine = document.getElementById("statusLine");
  const startBtn = document.getElementById("startBtn");
  const stopBtn = document.getElementById("stopBtn");
  const resetBtn = document.getElementById("resetBtn");
  const modeBtns = document.querySelectorAll(".mode-btn");

  progressRing.style.strokeDasharray = CIRC;

  function render() {
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    timeDisplay.textContent =
      String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
    progressRing.style.strokeDashoffset = CIRC * (1 - remaining / total);
    phaseLabel.textContent = LABELS[mode];
    focusBadge.textContent =
      sessionsDone + (sessionsDone === 1 ? " session" : " sessions") + " complete";
  }

  function setMode(m, silent) {
    mode = m;
    total = DURATIONS[m];
    remaining = total;
    modeBtns.forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === m);
    });
    if (!silent) statusLine.textContent = "Mode set to " + LABELS[m].toLowerCase() + ".";
    render();
  }

  function startTimer() {
    if (timerId) return;
    timerId = setInterval(tick, 1000);
    // After Start is pressed, lock the Stop button so it cannot be clicked.
    startBtn.disabled = true;
    stopBtn.disabled = true;
    setModeBtns(false);
    statusLine.textContent = "Focusing... stop is locked for this session.";
    render();
  }

  function tick() {
    remaining -= 1;
    if (remaining <= 0) {
      remaining = 0;
      render();
      clearInterval(timerId);
      timerId = null;
      onIntervalComplete();
      return;
    }
    render();
  }

  function onIntervalComplete() {
    if (mode === "focus") {
      sessionsDone += 1;
      // Cycle: focus -> short, every 4th focus -> long.
      const next = sessionsDone % 4 === 0 ? "long" : "short";
      setMode(next, true);
      statusLine.textContent = "Focus complete. Time for a " + LABELS[next].toLowerCase() + ".";
      showToast("Focus complete! Take a break.");
    } else {
      setMode("focus", true);
      statusLine.textContent = "Break over. Back to focus.";
      showToast("Break finished \u2014 back to focus.");
    }
    // Buttons are now unlocked (session ended, so Stop becomes clickable again).
    startBtn.disabled = false;
    stopBtn.disabled = false;
    setModeBtns(true);
  }

  function setModeBtns(enable) {
    modeBtns.forEach((b) => (b.disabled = !enable));
  }

  function stopTimer() {
    if (timerId) return; // Stop is disabled during run anyway.
    // Idle stop: reset current session's clock back to full.
    remaining = total;
    statusLine.textContent = "Stopped. Timer reset for " + LABELS[mode].toLowerCase() + ".";
    render();
  }

  function resetTimer() {
    clearInterval(timerId);
    timerId = null;
    remaining = total;
    startBtn.disabled = false;
    stopBtn.disabled = false;
    setModeBtns(true);
    statusLine.textContent = "Reset. Ready when you are.";
    render();
  }

  function initTimer() {
    startBtn.addEventListener("click", startTimer);
    stopBtn.addEventListener("click", stopTimer);
    resetBtn.addEventListener("click", resetTimer);
    modeBtns.forEach((b) =>
      b.addEventListener("click", () => {
        if (timerId) return; // ignore during running session
        setMode(b.dataset.mode);
      })
    );
    render();
    return Promise.resolve();
  }

  /* ==================================================================
   * Change password
   * ================================================================== */
  const pwModal = document.getElementById("pwModal");
  const pwForm = document.getElementById("pwForm");
  const pwError = document.getElementById("pwError");
  const pwSubmitBtn = document.getElementById("pwSubmit");

  function openPwModal() {
    pwError.classList.remove("show");
    pwForm.reset();
    pwModal.hidden = false;
    document.getElementById("pwCurrent").focus();
  }

  function closePwModal() {
    pwModal.hidden = true;
  }

  document.getElementById("pwCancel").addEventListener("click", closePwModal);
  pwModal.addEventListener("click", (e) => {
    if (e.target === pwModal) closePwModal();
  });

  document.getElementById("changePwBtn").addEventListener("click", openPwModal);

  pwForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const current = document.getElementById("pwCurrent").value;
    const next = document.getElementById("pwNew").value;
    const confirm = document.getElementById("pwConfirm").value;

    pwError.classList.remove("show");
    if (next !== confirm) {
      pwError.textContent = "New passwords do not match.";
      pwError.classList.add("show");
      return;
    }
    if (next.length < 6) {
      pwError.textContent = "New password must be at least 6 characters.";
      pwError.classList.add("show");
      return;
    }

    pwSubmitBtn.disabled = true;
    pwSubmitBtn.textContent = "Updating...";
    try {
      const res = await API.request("/api/password", {
        method: "POST",
        body: JSON.stringify({ current, next }),
      });
      if (res.status === 200) {
        closePwModal();
        showToast("Password updated.");
      } else {
        pwError.textContent = res.data.error || "Could not update password.";
        pwError.classList.add("show");
      }
    } catch (err) {
      pwError.textContent = "Network error. Please try again.";
      pwError.classList.add("show");
    } finally {
      pwSubmitBtn.disabled = false;
      pwSubmitBtn.textContent = "Update";
    }
  });

  /* ==================================================================
   * Logout
   * ================================================================== */
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await API.request("/api/logout", { method: "POST" });
    window.location.href = "/login.html";
  });

  boot();
})();