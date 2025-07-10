const output = document.getElementById('output');
const input = document.getElementById('cli-input');
const grid = document.getElementById('ttp-grid');

const THREATFOX_KEY = "T*d-ot,v9^y2cOsB9#sMNS_]4w:e7hjs`70<+j+`";
const OTX_KEY = "41d86ff8802344a81459bcac90dd9e1398c65333024c32a612f63ae0351578df";

function logOutput(text) {
  output.innerHTML += `> ${text}<br>`;
  output.scrollTop = output.scrollHeight;
}

function simulateMITREFlashes() {
  grid.innerHTML = '';
  const ttpIds = ['T1059', 'T1547', 'T1027', 'T1055', 'T1036'];
  ttpIds.forEach(ttp => {
    const div = document.createElement('div');
    div.className = 'ttp';
    div.textContent = ttp;
    grid.appendChild(div);
  });
}

async function fetchThreatFox() {
  try {
    const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_recent", limit: 3 })
    });
    const json = await res.json();
    logOutput("Recent ThreatFox IOCs:");
    json.data.forEach(ioc => logOutput(`${ioc.ioc} [${ioc.malware} - ${ioc.tags}]`));
  } catch (err) {
    logOutput("Error fetching from ThreatFox.");
  }
}

async function fetchFeodo() {
  try {
    const res = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.json");
    const json = await res.json();
    logOutput("Top Feodo Botnet IPs:");
    json.data.slice(0, 5).forEach(ip => logOutput(`${ip.ip_address} (${ip.asn_name})`));
  } catch (err) {
    logOutput("Error fetching from Feodo Tracker.");
  }
}

async function fetchOTX() {
  try {
    const res = await fetch("https://otx.alienvault.com/api/v1/pulses/subscribed", {
      headers: { "X-OTX-API-KEY": OTX_KEY }
    });
    const json = await res.json();
    logOutput("Top OTX Pulses:");
    json.results.slice(0, 3).forEach(p => logOutput(`${p.name} (${p.created})`));
  } catch (err) {
    logOutput("Error fetching from OTX.");
  }
}

input.addEventListener("keydown", async e => {
  if (e.key === "Enter") {
    const cmd = input.value.trim().toLowerCase();
    input.value = "";
    switch (cmd) {
      case "feedscan": await fetchThreatFox(); break;
      case "iotx": await fetchOTX(); break;
      case "feodo": await fetchFeodo(); break;
      case "ghostsec --hunt": simulateMITREFlashes(); logOutput("Running MITRE flash simulator..."); break;
      default: logOutput(`Unknown command: ${cmd}`);
    }
  }
});
