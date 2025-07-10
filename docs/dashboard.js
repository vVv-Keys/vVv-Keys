
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("terminal-input");
  const output = document.getElementById("terminal-output");

  const fakeCommands = {
    ghostsec: "Launching GhostSec Core modules...",
    academy: "Accessing KeysGuard Academy...",
    feedscan: "Fetching latest IoCs from ThreatFox...",
    help: "Available: ghostsec, academy, feedscan, mitre"
  };

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const cmd = input.value.trim();
      const response = fakeCommands[cmd] || "Unknown command.";
      const line = document.createElement("div");
      line.innerHTML = `> ${cmd}<br/>${response}`;
      output.insertBefore(line, input);
      input.value = "";
      window.scrollTo(0, document.body.scrollHeight);
    }
  });

  // MITRE grid simulator
  const canvas = document.getElementById("mitre-canvas");
  const ctx = canvas.getContext("2d");
  const cols = 8, rows = 5;
  const boxSize = 40;
  for (let y = 0; y < rows; y++) {
    for (let x = 0; x < cols; x++) {
      const threat = Math.random() > 0.7;
      ctx.fillStyle = threat ? "#ff5555" : "#004d40";
      ctx.fillRect(x * boxSize, y * boxSize, boxSize - 2, boxSize - 2);
    }
  }
});
