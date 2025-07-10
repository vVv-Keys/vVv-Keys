document.getElementById("cli-input").addEventListener("keydown", function(event) {
  if (event.key === "Enter") {
    const cmd = this.value.trim();
    const output = document.getElementById("cli-output");
    const status = document.getElementById("threat-status");
    output.innerHTML += `> ${cmd}\n`;

    if (cmd === "feedscan") {
      output.innerHTML += "[+] Pulling ThreatFox feed...\n";
      output.innerHTML += "[+] IOC found: T1059.003\n";
      document.querySelectorAll(".ttp-cell").forEach(el => el.classList.remove("ttp-hit"));
      document.querySelector('[data-ttp="T1059.003"]').classList.add("ttp-hit");
      status.textContent = "🔥 ThreatFox IOC matched: T1059.003";
    } else {
      output.innerHTML += "[-] Unknown command\n";
      status.textContent = "❌ No threat feed activity.";
    }
    this.value = "";
  }
});
